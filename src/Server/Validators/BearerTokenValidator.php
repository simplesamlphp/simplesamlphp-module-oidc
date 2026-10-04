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
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Throwable;

use function apache_request_headers;
use function array_key_exists;
use function count;
use function is_array;
use function preg_match;
use function trim;

class BearerTokenValidator implements AuthorizationValidatorInterface
{
    public function __construct(
        protected readonly AccessTokenRepository $accessTokenRepository,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jws $jws,
        protected readonly Jwks $jwks,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * {@inheritdoc}
     *
     * Refusals are shaped as RFC 6750 section 3.1 has them: a request with no Bearer token gets the bare challenge
     * and no error code, one whose token fails a check gets `invalid_token`, and a failure of the OP's own while
     * checking is a `server_error`.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $jwt = null;

        if (
            $request->hasHeader('authorization') &&
            ($header = $request->getHeader('authorization')) &&
            ($accessToken = $this->getTokenFromAuthorizationBearer($header[0])) !== null
        ) {
            $jwt = $accessToken;
        } elseif (
            strcasecmp($request->getMethod(), 'POST') === 0 &&
            is_array($parsedBody = $request->getParsedBody()) &&
            isset($parsedBody['access_token']) &&
            is_string($parsedBody['access_token'])
        ) {
            $jwt = $parsedBody['access_token'];
        } elseif (
            // Handle case when Apache strips of Authorization header with Bearer scheme.
            // https://github.com/symfony/symfony/issues/19693
            // Although we actually handle it here, it has performance implications, so give warning about it.
            is_callable('apache_request_headers') &&
            ($headers = array_change_key_case(apache_request_headers())) &&
            (array_key_exists('authorization', $headers)) &&
            ($header = (string)$headers['authorization']) &&
            ($accessToken = $this->getTokenFromAuthorizationBearer($header)) !== null
        ) {
            $this->loggerService->warning(
                'Apache stripping of Authorization Bearer request header encountered. You should modify your' .
                ' Apache configuration to preserve to Authorization Bearer token in requests to avoid performance ' .
                'implications. Check the OIDC module documentation on how to do that.',
            );
            $jwt = $accessToken;
        }

        if (!is_string($jwt) || $jwt === '') {
            throw OidcServerException::missingToken(
                'No Bearer access token in the Authorization header or the access_token request body param.',
            );
        }

        try {
            $token = $this->ensureValidAccessToken($jwt);
            $jti = $token->getJwtId();
            $audience = $token->getAudience();
            $subject = $token->getSubject();
            /** @psalm-suppress MixedAssignment */
            $scopes = $token->getPayloadClaim('scopes');
            $type = $token->getType();
        } catch (OpenIdException | TokenNotFoundException $exception) {
            // The verdicts on the token: not a JWS of ours, not an access token, expired, revoked or malformed (the
            // library's exceptions), or no record of it (the repository's). The same split the introspection
            // endpoint makes.
            throw OidcServerException::invalidToken($exception->getMessage(), $exception);
        } catch (Throwable $exception) {
            // A failure of the OP's own while checking the token: a database which did not answer, a corrupt
            // record, a signing key configuration which can not be read. Answered as a verdict, it would tell a
            // client holding a working token to throw it away, and hide the outage behind a 401.
            throw OidcServerException::serverError('The access token could not be checked.', $exception);
        }

        if (is_null($jti) || empty($jti)) {
            throw OidcServerException::invalidToken('Access token malformed (jti missing or unexpected type)');
        }

        // Return the request with additional attributes. 'oauth_user_id' is the token's 'sub' (league's name for
        // it); 'oauth_access_token_typ' is the JWT 'typ' header, null for an access token minted before the module
        // wrote one, so a consumer can tell a token whose 'sub' is the resolved subject from one whose 'sub' is
        // the internal user identifier (see UserInfoController).
        return $request
            ->withAttribute('oauth_access_token_id', $jti)
            ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($audience))
            ->withAttribute('oauth_user_id', $subject)
            ->withAttribute('oauth_scopes', $scopes)
            ->withAttribute('oauth_access_token_typ', $type);
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
     * The access token an Authorization header carries under the Bearer scheme, or null for a header under another
     * scheme or with nothing after the scheme name. The scheme name is matched case-insensitively, as HTTP has it
     * (RFC 9110 section 11.1). A header under another scheme carries no bearer token, so a request which sent only
     * that is refused as one which sent none (RFC 6750 section 3.1), not as one whose token was found wanting.
     */
    protected function getTokenFromAuthorizationBearer(string $authorizationHeader): ?string
    {
        if (preg_match('/^\s*Bearer(?:\s+(.*))?$/is', $authorizationHeader, $matches) !== 1) {
            return null;
        }

        $token = trim($matches[1] ?? '');

        return $token === '' ? null : $token;
    }


    /**
     * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
     *
     * @param mixed $aud
     *
     * @return array|string
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function convertSingleRecordAudToString(mixed $aud): array|string
    {
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

        throw OidcServerException::invalidToken('Unexpected aud claim value.');
    }
}
