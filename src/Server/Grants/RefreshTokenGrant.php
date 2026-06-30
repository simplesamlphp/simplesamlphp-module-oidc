<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use Exception;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant as OAuth2RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;

use function is_null;
use function json_decode;
use function time;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class RefreshTokenGrant extends OAuth2RefreshTokenGrant
{
    use IssueAccessTokenTrait;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        AccessTokenEntityFactory $accessTokenEntityFactory,
        protected readonly RefreshTokenIssuer $refreshTokenIssuer,
        protected readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        protected readonly LoggerService $loggerService,
    ) {
        parent::__construct($refreshTokenRepository);
        $this->accessTokenEntityFactory = $accessTokenEntityFactory;
    }

    /**
     * Authenticate the client at the refresh token endpoint without requiring a `client_id` request
     * parameter. The league default (AbstractGrant::validateClient) resolves the client from a
     * client_id parameter or HTTP Basic username, which a private_key_jwt client does not send - it
     * conveys its identity via the `client_assertion` JWT. This mirrors how the authorization_code
     * grant authenticates the caller (via ClientAuthenticationRule, which uses the same resolver), so
     * all supported authentication methods (private_key_jwt, client_secret_basic, client_secret_post
     * and public/none) work consistently across the token endpoint.
     *
     * The refresh token is still bound to a specific client: validateOldRefreshToken() checks that the
     * authenticated client matches the client the refresh token was issued to.
     *
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    protected function validateClient(ServerRequestInterface $request): ClientEntityInterface
    {
        $resolvedClientAuthenticationMethod = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request);

        if ($resolvedClientAuthenticationMethod === null) {
            $this->loggerService->warning(
                'Refresh token request rejected: client authentication failed (no supported client ' .
                'authentication method could be resolved).',
            );
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::CLIENT_AUTHENTICATION_FAILED, $request));
            throw OAuthServerException::invalidClient($request);
        }

        return $resolvedClientAuthenticationMethod->getClient();
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (is_null($encryptedRefreshToken)) {
            $this->loggerService->notice(
                'Refresh token request rejected: `refresh_token` parameter not provided.',
                ['client_id' => $clientId],
            );
            throw OidcServerException::invalidGrant('Failed to verify `refresh_token`');
        }

        // Validate refresh token
        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            $this->loggerService->warning(
                'Refresh token request rejected: could not decrypt the refresh token.',
                ['client_id' => $clientId, 'exception' => $e->getMessage()],
            );
            throw OidcServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
        }

        $refreshTokenData = json_decode($refreshToken, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($refreshTokenData)) {
            $this->loggerService->warning(
                'Refresh token request rejected: decrypted refresh token has an unexpected type.',
                ['client_id' => $clientId],
            );
            throw OidcServerException::invalidRefreshToken('Refresh token has unexpected type');
        }

        /** @var array<string, mixed> $refreshTokenData */
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->loggerService->warning(
                'Refresh token request rejected: refresh token is not linked to the authenticated client.',
                [
                    'client_id' => $clientId,
                    'refresh_token_client_id' => $refreshTokenData['client_id'],
                    'refresh_token_id' => $refreshTokenData['refresh_token_id'] ?? null,
                ],
            );
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OidcServerException::invalidRefreshToken('Refresh token is not linked to client');
        }

        if ($refreshTokenData['expire_time'] < time()) {
            $this->loggerService->notice(
                'Refresh token request rejected: refresh token has expired.',
                [
                    'client_id' => $clientId,
                    'refresh_token_id' => $refreshTokenData['refresh_token_id'] ?? null,
                ],
            );
            throw OidcServerException::invalidRefreshToken('Refresh token has expired');
        }

        if (
            $this->refreshTokenRepository->isRefreshTokenRevoked(
                (string)$refreshTokenData['refresh_token_id'],
            ) === true
        ) {
            $this->loggerService->warning(
                'Refresh token request rejected: refresh token has been revoked.',
                [
                    'client_id' => $clientId,
                    'refresh_token_id' => $refreshTokenData['refresh_token_id'] ?? null,
                ],
            );
            throw OidcServerException::invalidRefreshToken('Refresh token has been revoked');
        }

        // The OIDC Conformance suite checks that the refreshed ID Token's `iat` (issued at)
        // claim is different from the initial ID Token's `iat`. When running locally in a fast
        // Docker/WSL environment, the initial exchange and subsequent refresh request can
        // happen within the same second, resulting in the same `iat` value.
        // We reconstruct the old token's issue time using its expiration timestamp and TTL.
        // If the current time is still the same second as the original issuance, we sleep
        // for 1 second to guarantee the new ID Token gets a different, updated `iat`.
        if (isset($refreshTokenData['expire_time'])) {
            $reference = new \DateTimeImmutable();
            $endTime = $reference->add($this->refreshTokenTTL);
            $ttlSeconds = $endTime->getTimestamp() - $reference->getTimestamp();
            $oldIssueTime = ((int)$refreshTokenData['expire_time']) - $ttlSeconds;

            if (time() === $oldIssueTime) {
                sleep(1);
            }
        }

        return $refreshTokenData;
    }

    protected function issueRefreshToken(
        OAuth2AccessTokenEntityInterface $accessToken,
        ?string $authCodeId = null,
    ): ?RefreshTokenEntityInterface {
        if (! is_a($accessToken, AccessTokenEntityInterface::class)) {
            throw OidcServerException::serverError('Unexpected access token entity type.');
        }

        return $this->refreshTokenIssuer->issue(
            $accessToken,
            $this->refreshTokenTTL,
            $authCodeId,
            self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS,
        );
    }
}
