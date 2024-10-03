<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants;

use Exception;
use League\OAuth2\Server\Grant\RefreshTokenGrant as OAuth2RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestEvent;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Traits\IssueAccessTokenTrait;

use function is_null;
use function json_decode;
use function time;

class RefreshTokenGrant extends OAuth2RefreshTokenGrant
{
    use IssueAccessTokenTrait;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $revokeRefreshTokens;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $defaultScope;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $privateKey;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $userRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $authCodeRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $scopeRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $accessTokenRepository;

    /** @psalm-suppress PropertyNotSetInConstructor */
    protected $clientRepository;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        AccessTokenEntityFactory $accessTokenEntityFactory,
    ) {
        parent::__construct($refreshTokenRepository);
        $this->accessTokenEntityFactory = $accessTokenEntityFactory;
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, $clientId): array
    {
        $encryptedRefreshToken = $this->getRequestParameter('refresh_token', $request);
        if (is_null($encryptedRefreshToken)) {
            throw OidcServerException::invalidGrant('Failed to verify `refresh_token`');
        }

        // Validate refresh token
        try {
            $refreshToken = $this->decrypt($encryptedRefreshToken);
        } catch (Exception $e) {
            throw OidcServerException::invalidRefreshToken('Cannot decrypt the refresh token', $e);
        }

        $refreshTokenData = json_decode($refreshToken, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($refreshTokenData)) {
            throw OidcServerException::invalidRefreshToken('Refresh token has unexpected type');
        }
        if ($refreshTokenData['client_id'] !== $clientId) {
            $this->getEmitter()->emit(new RequestEvent(RequestEvent::REFRESH_TOKEN_CLIENT_FAILED, $request));
            throw OidcServerException::invalidRefreshToken('Refresh token is not linked to client');
        }

        if ($refreshTokenData['expire_time'] < time()) {
            throw OidcServerException::invalidRefreshToken('Refresh token has expired');
        }

        if (
            $this->refreshTokenRepository->isRefreshTokenRevoked(
                (string)$refreshTokenData['refresh_token_id'],
            ) === true
        ) {
            throw OidcServerException::invalidRefreshToken('Refresh token has been revoked');
        }

        return $refreshTokenData;
    }
}
