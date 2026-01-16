<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Validators;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;

use function count;
use function is_array;
use function preg_replace;
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
            // Attempt to parse the JWT
            $token = $this->jws->parsedJwsFactory()->fromToken($jwt);
        } catch (JwsException $exception) {
            throw OidcServerException::accessDenied($exception->getMessage(), null, $exception);
        }

        try {
            // Attempt to validate the JWT
            $jwks = $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
                ...$this->moduleConfig->getConnectSignatureKeyPairBag()->getAllPublicKeys(),
            )->jsonSerialize();
            $token->verifyWithKeySet($jwks);
        } catch (JwsException) {
            throw OidcServerException::accessDenied('Access token could not be verified');
        }

        if (is_null($jti = $token->getJwtId()) || empty($jti)) {
            throw OidcServerException::accessDenied('Access token malformed (jti missing or unexpected type)');
        }

        // Check if token has been revoked
        if ($this->accessTokenRepository->isAccessTokenRevoked($jti)) {
            throw OidcServerException::accessDenied('Access token has been revoked');
        }

        // Return the request with additional attributes
        return $request
            ->withAttribute('oauth_access_token_id', $jti)
            ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($token->getAudience()))
            ->withAttribute('oauth_user_id', $token->getSubject())
            ->withAttribute('oauth_scopes', $token->getPayloadClaim('scopes'));
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
    protected function convertSingleRecordAudToString(mixed $aud): array|string
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
