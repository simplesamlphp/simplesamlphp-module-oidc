<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Throwable;

use function apache_request_headers;
use function array_push;
use function count;
use function hash_equals;
use function is_array;
use function preg_match;
use function strcasecmp;
use function strlen;
use function trim;

/**
 * Checks the access token a request to a protected resource presents: under the Bearer scheme (RFC 6750) or, for
 * a token bound to a key, under the DPoP scheme (RFC 9449). The name stays from when Bearer was the only one.
 */
class BearerTokenValidator implements AuthorizationValidatorInterface
{
    /**
     * The request attribute a protected resource names its own URL in, as this OP publishes it: the URL the `htu`
     * of a DPoP proof has to name (ResourceServer sets it).
     */
    public const string ATTRIBUTE_RESOURCE_URL = 'oidc_protected_resource_url';

    /**
     * The request attribute the scheme the access token was presented under is passed on in: `Bearer` (the
     * Authorization header under that scheme, or the request body) or `DPoP`.
     */
    public const string ATTRIBUTE_ACCESS_TOKEN_SCHEME = 'oauth_access_token_scheme';

    /**
     * The start of an auth-param (RFC 9110 section 11.2): a token, optional blanks and "=".
     */
    protected const string AUTH_PARAM_START_PATTERN = '/^\s*[!#$%&\'*+.^_`|~0-9A-Za-z-]+\s*=/';


    public function __construct(
        protected readonly AccessTokenRepository $accessTokenRepository,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jws $jws,
        protected readonly Jwks $jwks,
        protected readonly LoggerService $loggerService,
        protected readonly DpopProofVerifier $dpopProofVerifier,
    ) {
    }


    /**
     * {@inheritdoc}
     *
     * The access token comes in the Authorization header, under the Bearer scheme (RFC 6750 section 2.1) or the
     * DPoP scheme (RFC 9449 section 7.1), or in the body of a POST request (RFC 6750 section 2.2). A request which
     * uses more than one of these, or carries more than one Authorization header value, is refused as
     * `invalid_request` and no token is checked (RFC 6750 sections 2 and 3.1, RFC 9449 section 7.2).
     *
     * Refusals are shaped as RFC 6750 section 3.1 has them: a request with no access token gets challenges with no
     * error code, one whose token fails a check gets `invalid_token`, and a failure of the OP's own while checking
     * is a `server_error`. Both schemes are challenged, as RFC 9449 section 7.2 recommends for a resource which
     * takes both (challenge()): a token refused under the DPoP scheme gets the DPoP challenge alone, and every
     * DPoP challenge names the algorithms a proof may be signed with (section 7.1).
     *
     * A token bound to a key is accepted only under the DPoP scheme, with a proof by that key, and only a token
     * bound to a key is accepted under it (ensureSenderConstraint()).
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        [$scheme, $jwt] = $this->getPresentedAccessToken($request);

        try {
            $token = $this->ensureValidAccessToken($jwt);
            $jti = $token->getJwtId();
            $audience = $token->getAudience();
            $subject = $token->getSubject();
            /** @psalm-suppress MixedAssignment */
            $scopes = $token->getPayloadClaim('scopes');
            $type = $token->getType();
            $hasConfirmation = $token->hasPayloadClaim(ClaimsEnum::Cnf->value);
            /** @psalm-suppress MixedAssignment */
            $confirmation = $token->getPayloadClaim(ClaimsEnum::Cnf->value);
        } catch (OpenIdException | TokenNotFoundException $exception) {
            // The verdicts on the token: not a JWS of ours, not an access token, expired, revoked or malformed (the
            // library's exceptions), or no record of it (the repository's). The same split the introspection
            // endpoint makes.
            throw OidcServerException::invalidToken(
                $exception->getMessage(),
                $exception,
                $this->challenge($scheme, 'invalid_token'),
            );
        } catch (Throwable $exception) {
            // A failure of the OP's own while checking the token: a database which did not answer, a corrupt
            // record, a signing key configuration which can not be read. Answered as a verdict, it would tell a
            // client holding a working token to throw it away, and hide the outage behind a 401.
            throw OidcServerException::serverError('The access token could not be checked.', $exception);
        }

        if (is_null($jti) || empty($jti)) {
            throw OidcServerException::invalidToken(
                'Access token malformed (jti missing or unexpected type)',
                null,
                $this->challenge($scheme, 'invalid_token'),
            );
        }

        $clientId = $this->convertSingleRecordAudToString($audience, $scheme);

        $this->ensureSenderConstraint($request, $scheme, $jwt, $hasConfirmation, $confirmation);

        // Return the request with additional attributes. 'oauth_user_id' is the token's 'sub' (league's name for
        // it); 'oauth_access_token_typ' is the JWT 'typ' header, null for an access token minted before the module
        // wrote one, so a consumer can tell a token whose 'sub' is the resolved subject from one whose 'sub' is
        // the internal user identifier (see UserInfoController).
        return $request
            ->withAttribute('oauth_access_token_id', $jti)
            ->withAttribute('oauth_client_id', $clientId)
            ->withAttribute('oauth_user_id', $subject)
            ->withAttribute('oauth_scopes', $scopes)
            ->withAttribute('oauth_access_token_typ', $type)
            ->withAttribute(self::ATTRIBUTE_ACCESS_TOKEN_SCHEME, $scheme->value);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function ensureValidAccessToken(string $accessTokenJwt): ParsedJws
    {
        // Attempt to parse the JWT
        $token = $this->jws->parsedJwsFactory()->fromToken($accessTokenJwt);

        // Attempt to validate the JWT
        $jwks = $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
            ...$this->moduleConfig->getProtocolSignatureKeyPairBag()->getAllPublicKeys(),
        )->jsonSerialize();

        try {
            $token->verifyWithKeySet($jwks);
        } catch (Throwable $e) {
            // The library's verifier hands the JOSE library's own exceptions through for a header it can not work
            // with (an 'alg' which is missing, unsupported or not a string); whatever the reason, a token which can
            // not be verified is refused as one, so that a caller can tell that verdict from a failure of its own.
            throw new JwsException('Access token signature could not be verified: ' . $e->getMessage(), 0, $e);
        }

        $token->getExpirationTime();

        $this->ensureAccessTokenType($token);

        if (is_null($iss = $token->getIssuer()) || empty($iss)) {
            throw new JwsException('Access token malformed (iss missing or unexpected type)');
        }

        if ($iss !== $this->moduleConfig->getIssuer()) {
            throw new JwsException('Access token malformed (iss does not match)');
        }

        if (is_null($jti = $token->getJwtId()) || empty($jti)) {
            throw new JwsException('Access token malformed (jti missing or unexpected type)');
        }

        // Check if the token has been revoked
        if ($this->accessTokenRepository->isAccessTokenRevoked($jti)) {
            throw new JwsException('Access token has been revoked');
        }

        return $token;
    }


    /**
     * RFC 9068 section 4: the resource server rejects a token whose "typ" header is anything other than
     * "at+jwt" / "application/at+jwt". The value is compared as RFC 7515 section 4.1.9 prescribes (media
     * types are case-insensitive; "application/" is implied when the value has no '/'), which the library's
     * MediaType helper does; it is the comparison the library's own JwtAccessToken makes at construction.
     * An absent "typ" is still accepted: access tokens minted by earlier module versions carry no "typ" and
     * remain valid until they expire, and an ID token or logout token can not pass as an access token
     * anyway, since the "jti" lookup in ensureValidAccessToken() only knows access token identifiers. Once
     * that grace period is over, the token is to be parsed as a JwtAccessToken instead, which needs "typ".
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    protected function ensureAccessTokenType(ParsedJws $token): void
    {
        if (!$token->hasHeaderClaim(ClaimsEnum::Typ->value)) {
            return;
        }

        // Present, so it has to be a string (getType() refuses other types); an explicit null is not "absent".
        $typ = $token->getType();
        if (is_null($typ)) {
            throw new JwsException('Access token malformed (typ missing or unexpected type)');
        }

        if (!$this->jws->helpers()->mediaType()->areJwtTypesEqual($typ, JwtTypesEnum::AtJwt->value)) {
            throw new JwsException('Access token malformed (typ is not at+jwt)');
        }
    }


    /**
     * RFC 9449 section 7.2 has a resource which accepts both schemes "reject a DPoP-bound access token received as
     * a bearer token", and section 7.1 has it check, for a token presented under the DPoP scheme, that a proof
     * came, that it is valid, and that its key is the one the token is bound to.
     *
     * Any `cnf` claim, an explicit null included, makes a token one which is bound, so such a token is refused
     * under the Bearer scheme and in the request body: the module writes the claim only to bind a token, and the
     * access token claim list may not name it (ModuleConfig::RESERVED_CLAIM_NAMES). Under the DPoP scheme the
     * token has to carry `cnf.jkt`, the thumbprint of the key it is bound to (section 6.1); else it is no
     * DPoP-bound access token, and is refused as `invalid_token`. Then the proof: a missing one, or one which
     * fails a check (DpopProofVerifier, which also checks that it carries this token's hash), is
     * `invalid_dpop_proof`; a proof by another key is `invalid_token`, as section 7.1 (Figure 16) answers it.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function ensureSenderConstraint(
        ServerRequestInterface $request,
        AccessTokenTypesEnum $scheme,
        string $accessToken,
        bool $hasConfirmation,
        mixed $confirmation,
    ): void {
        if ($scheme !== AccessTokenTypesEnum::DPoP) {
            if ($hasConfirmation) {
                throw OidcServerException::invalidToken(
                    'The access token is bound to a key and can be presented only under the DPoP scheme.',
                    null,
                    $this->challenge($scheme, 'invalid_token'),
                );
            }

            return;
        }

        /** @psalm-suppress MixedAssignment */
        $boundJwkThumbprint = is_array($confirmation) ? ($confirmation[ClaimsEnum::Jkt->value] ?? null) : null;
        if (!is_string($boundJwkThumbprint) || $boundJwkThumbprint === '') {
            throw OidcServerException::invalidToken(
                'The access token is not a DPoP-bound access token.',
                null,
                $this->challenge($scheme, 'invalid_token'),
            );
        }

        $resourceUrl = $request->getAttribute(self::ATTRIBUTE_RESOURCE_URL);
        if (!is_string($resourceUrl) || $resourceUrl === '') {
            throw OidcServerException::serverError(
                'The protected resource did not name its URL, so the DPoP proof can not be checked.',
            );
        }

        $verifiedDpopProof = $this->dpopProofVerifier->verify($request, $resourceUrl, $accessToken);
        if ($verifiedDpopProof === null) {
            throw OidcServerException::invalidDpopProof(
                'A DPoP proof is required with a DPoP-bound access token.',
                $this->challenge($scheme, ErrorsEnum::InvalidDpopProof->value),
            );
        }

        if (!hash_equals($boundJwkThumbprint, $verifiedDpopProof->getJwkThumbprint())) {
            throw OidcServerException::invalidToken(
                'The DPoP proof is not signed by the key the access token is bound to.',
                null,
                $this->challenge($scheme, 'invalid_token'),
            );
        }
    }


    /**
     * The access token the request presents, and the scheme it presents it under.
     *
     * @return array{0: \SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum, 1: non-empty-string}
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function getPresentedAccessToken(ServerRequestInterface $request): array
    {
        $credentials = $this->getAuthorizationCredentials($request);
        $headerToken = count($credentials) === 1 ? $this->getTokenFromAuthorizationHeader($credentials[0]) : null;
        $bodyToken = $this->getTokenFromRequestBody($request);

        if (count($credentials) > 1 || ($headerToken !== null && $bodyToken !== null)) {
            throw OidcServerException::multipleAccessTokenMethods($this->challenge(null, 'invalid_request'));
        }

        if ($headerToken !== null) {
            return $headerToken;
        }

        if ($bodyToken !== null) {
            return [AccessTokenTypesEnum::Bearer, $bodyToken];
        }

        // A request which names a scheme with nothing after it carried no credentials either.
        throw OidcServerException::missingToken(
            'No access token in the Authorization header or the access_token request body param.',
            $this->challenge(null),
        );
    }


    /**
     * The values of the Authorization header field, each one credentials. The field may come more than once, and
     * a server joins repeated fields into one value with commas (RFC 9110 section 5.3), so the value is split at
     * them (splitCredentials()). A request without the field is read through apache_request_headers(), for an
     * Apache which strips the header from what PHP is given (https://github.com/symfony/symfony/issues/19693);
     * every entry whose name is Authorization in any case is taken, so that none is lost to another.
     *
     * @return string[]
     */
    protected function getAuthorizationCredentials(ServerRequestInterface $request): array
    {
        $values = $request->getHeader('authorization');

        if ($values === []) {
            /** @psalm-suppress MixedAssignment */
            foreach ($this->getApacheRequestHeaders() as $name => $value) {
                if (strcasecmp((string)$name, 'authorization') === 0) {
                    $values[] = (string)$value;
                }
            }

            if ($values !== []) {
                // Although it is handled here, it has performance implications, so give a warning about it.
                $this->loggerService->warning(
                    'Apache stripping of Authorization Bearer request header encountered. You should modify your' .
                    ' Apache configuration to preserve to Authorization Bearer token in requests to avoid ' .
                    'performance implications. Check the OIDC module documentation on how to do that.',
                );
            }
        }

        $credentials = [];
        foreach ($values as $value) {
            array_push($credentials, ...$this->splitCredentials($value));
        }

        return $credentials;
    }


    /**
     * One Authorization field value split into the credentials it holds. A comma separates two of them where a
     * server joined repeated fields (RFC 9110 section 5.3), but also the auth-params of one (`Digest
     * username="alice", realm="op"`, RFC 9110 section 11.4), and it may sit in a quoted-string. So the value is
     * split at the commas outside quoted-strings, and an element which is an auth-param (a token, then "=") goes
     * with the credentials before it; an element which starts with anything else starts new credentials, as
     * every Bearer or DPoP value does (an auth-scheme, then its token68). An empty element is skipped (RFC 9110
     * section 5.6.1).
     *
     * @return string[]
     */
    protected function splitCredentials(string $value): array
    {
        $elements = [];
        $element = '';
        $isQuoted = false;
        $length = strlen($value);

        for ($i = 0; $i < $length; $i++) {
            $character = $value[$i];

            if ($isQuoted && $character === '\\' && $i + 1 < $length) {
                // A quoted-pair: the character after the backslash is taken as it is, a quote included.
                $element .= $character . $value[++$i];
                continue;
            }

            if ($character === '"') {
                $isQuoted = !$isQuoted;
            } elseif ($character === ',' && !$isQuoted) {
                $elements[] = $element;
                $element = '';
                continue;
            }

            $element .= $character;
        }
        $elements[] = $element;

        $credentials = [];
        foreach ($elements as $element) {
            if (trim($element) === '') {
                continue;
            }

            if ($credentials !== [] && preg_match(self::AUTH_PARAM_START_PATTERN, $element) === 1) {
                $credentials[count($credentials) - 1] .= ',' . $element;
                continue;
            }

            $credentials[] = $element;
        }

        return $credentials;
    }


    /**
     * The access token one Authorization header value carries, and its scheme: null for a value under another
     * scheme or with nothing after the scheme name. The scheme name is matched case-insensitively, as HTTP has it
     * (RFC 9110 section 11.1). A value under another scheme carries no access token, so a request which sent only
     * that is refused as one which sent none (RFC 6750 section 3.1), not as one whose token was found wanting.
     *
     * @return array{0: \SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum, 1: non-empty-string}|null
     */
    protected function getTokenFromAuthorizationHeader(string $credentials): ?array
    {
        if (preg_match('/^\s*(Bearer|DPoP)(?:\s+(.*))?$/is', $credentials, $matches) !== 1) {
            return null;
        }

        $token = trim($matches[2] ?? '');
        if ($token === '') {
            return null;
        }

        return [
            strcasecmp($matches[1], AccessTokenTypesEnum::DPoP->value) === 0 ?
                AccessTokenTypesEnum::DPoP :
                AccessTokenTypesEnum::Bearer,
            $token,
        ];
    }


    /**
     * The access token in the body of a POST request (RFC 6750 section 2.2), or null for none.
     *
     * @return non-empty-string|null
     */
    protected function getTokenFromRequestBody(ServerRequestInterface $request): ?string
    {
        if (strcasecmp($request->getMethod(), 'POST') !== 0) {
            return null;
        }

        $parsedBody = $request->getParsedBody();
        if (
            !is_array($parsedBody) ||
            !isset($parsedBody['access_token']) ||
            !is_string($parsedBody['access_token']) ||
            $parsedBody['access_token'] === ''
        ) {
            return null;
        }

        return $parsedBody['access_token'];
    }


    /**
     * The request headers as Apache has them, or none where PHP does not run under Apache.
     *
     * @return array<array-key,mixed>
     */
    protected function getApacheRequestHeaders(): array
    {
        if (!is_callable('apache_request_headers')) {
            return [];
        }

        /** @var mixed $headers */
        $headers = apache_request_headers();

        return is_array($headers) ? $headers : [];
    }


    /**
     * The challenges of a refusal (OidcServerException::buildResourceChallenges()): under the scheme the token was
     * presented under, or under both with none -- no credentials, or more than one method -- naming the error if
     * there is one.
     */
    protected function challenge(?AccessTokenTypesEnum $scheme, ?string $error = null): string
    {
        return OidcServerException::buildResourceChallenges(
            $scheme,
            $error,
            $this->moduleConfig->getDpopSigningAlgorithms(),
        );
    }


    /**
     * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
     *
     * @param mixed $aud
     * @param \SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum $scheme The scheme the token was presented under,
     * which a refusal is challenged in.
     *
     * @return array|string
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function convertSingleRecordAudToString(
        mixed $aud,
        AccessTokenTypesEnum $scheme = AccessTokenTypesEnum::Bearer,
    ): array|string {
        if (is_string($aud)) {
            return $aud;
        }

        if (is_array($aud) && !empty($aud)) {
            if (count($aud) === 1) {
                return (string)$aud[0];
            } else {
                return $aud;
            }
        }

        throw OidcServerException::invalidToken(
            'Unexpected aud claim value.',
            null,
            $this->challenge($scheme, 'invalid_token'),
        );
    }
}
