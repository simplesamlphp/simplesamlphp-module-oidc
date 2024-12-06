<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\TokenIssuers;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as Oauth2TokenEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;

class RefreshTokenIssuer extends AbstractTokenIssuer
{
    public function __construct(
        Helpers $helpers,
        protected readonly RefreshTokenRepository $refreshTokenRepository,
        protected readonly RefreshTokenEntityFactory $refreshTokenEntityFactory,
        protected readonly LoggerService $logger,
    ) {
        parent::__construct($helpers);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function issue(
        Oauth2TokenEntityInterface $accessToken,
        DateInterval $refreshTokenTtl,
        ?string $authCodeId = null,
        int $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS,
    ): ?RefreshTokenEntityInterface {
        if (! is_a($accessToken, AccessTokenEntityInterface::class)) {
            throw OidcServerException::serverError('Unexpected access token entity type.');
        }

        while ($maxGenerationAttempts-- > 0) {
            try {
                $refreshToken = $this->refreshTokenEntityFactory->fromData(
                    $this->helpers->random()->getIdentifier(),
                    (new DateTimeImmutable())->add($refreshTokenTtl),
                    $accessToken,
                    $authCodeId,
                );
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);
                return $refreshToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    $this->logger->error('Maximum generation attempts reached.', [
                        'maxGenerationAttempts' => $maxGenerationAttempts,
                        'accessTokenId' => $accessToken->getIdentifier(),
                        'authCodeId' => $authCodeId,
                    ]);
                    throw $e;
                }
            }
        }

        $this->logger->error('Unable to issue refresh token.', [
            'accessTokenId' => $accessToken->getIdentifier(),
            'authCodeId' => $authCodeId,
        ]);

        return null;
    }
}
