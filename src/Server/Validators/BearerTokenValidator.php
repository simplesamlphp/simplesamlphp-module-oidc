<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ContentTypesEnum;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use Throwable;

use function apache_request_headers;
use function array_key_exists;
use function count;
use function is_array;
use function preg_replace;
use function str_contains;
use function strtolower;
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
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        $jwt = null;

        if (
            $request->hasHeader('authorization') &&
            ($header = $request->getHeader('authorization')) &&
            ($accessToken = $this->getTokenFromAuthorizationBearer($header[0]))
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
            ($accessToken = $this->getTokenFromAuthorizationBearer($header))
        ) {
            $this->loggerService->warning(
                'Apache stripping of Authorization Bearer request header encountered. You should modify your' .
                ' Apache configuration to preserve to Authorization Bearer token in requests to avoid performance ' .
                'implications. Check the OIDC module documentation on how to do that.',
            );
            $jwt = $accessToken;
        }

        if (!is_string($jwt) || empty($jwt)) {
            throw OidcServerException::accessDenied('Missing Authorization header or access_token request body param.');
        }

        try {
            $token = $this->ensureValidAccessToken($jwt);
        } catch (Throwable $exception) {
            throw OidcServerException::accessDenied($exception->getMessage(), null, $exception);
        }

        if (is_null($jti = $token->getJwtId()) || empty($jti)) {
            throw OidcServerException::accessDenied('Access token malformed (jti missing or unexpected type)');
        }

        // Return the request with additional attributes. 'oauth_user_id' is the token's 'sub' (league's name for
        // it); 'oauth_access_token_typ' is the JWT 'typ' header, null for an access token minted before the module
        // wrote one, so a consumer can tell a token whose 'sub' is the resolved subject from one whose 'sub' is
        // the internal user identifier (see UserInfoController).
        return $request
            ->withAttribute('oauth_access_token_id', $jti)
            ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($token->getAudience()))
            ->withAttribute('oauth_user_id', $token->getSubject())
            ->withAttribute('oauth_scopes', $token->getPayloadClaim('scopes'))
            ->withAttribute('oauth_access_token_typ', $token->getType());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
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
        $token->verifyWithKeySet($jwks);

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
     * types are case-insensitive; "application/" is implied when the value has no '/'). An absent "typ" is
     * still accepted: access tokens minted by earlier module versions carry no "typ" and remain valid until
     * they expire, and an ID token or logout token can not pass as an access token anyway, since the "jti"
     * lookup in ensureValidAccessToken() only knows access token identifiers.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    protected function ensureAccessTokenType(ParsedJws $token): void
    {
        if (!array_key_exists(ClaimsEnum::Typ->value, $token->getHeader())) {
            return;
        }

        // Present, so it has to be a string (getType() refuses other types); an explicit null is not "absent".
        $typ = $token->getType();
        if (is_null($typ)) {
            throw new JwsException('Access token malformed (typ missing or unexpected type)');
        }

        $mediaType = strtolower($typ);
        if (!str_contains($mediaType, '/')) {
            $mediaType = 'application/' . $mediaType;
        }

        if ($mediaType !== ContentTypesEnum::ApplicationAtJwt->value) {
            throw new JwsException('Access token malformed (typ is not at+jwt)');
        }
    }


    protected function getTokenFromAuthorizationBearer(string $authorizationHeader): string
    {
        return trim((string) preg_replace('/^\s*Bearer\s/', '', $authorizationHeader));
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

        throw OidcServerException::accessDenied('Unexpected aud claim value.');
    }
}
