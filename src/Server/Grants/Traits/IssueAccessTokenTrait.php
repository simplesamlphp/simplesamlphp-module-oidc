<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants\Traits;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AbstractGrant;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * Trait IssueAccessTokenTrait
 * Certain parts of AbstractGrant are difficult to extend. This trait takes issueToken from AbstractGrant that we want
 * to change for our grants
 * @package SimpleSAML\Module\oidc\Server\Grants\Traits
 */
trait IssueAccessTokenTrait
{
    /**
     * @psalm-suppress MissingPropertyType
     */
    protected $accessTokenRepository;

    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * Issue an access token.
     *
     * @param string|null $userIdentifier
     * @param ScopeEntityInterface[] $scopes
     * @param array|null $requestedClaims Any requested claims
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier = null,
        array $scopes = [],
        string $authCodeId = null,
        array $requestedClaims = null,
    ): AccessTokenEntityInterface {
        $maxGenerationAttempts = AbstractGrant::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        /** Since we are using our own repository interface, check for proper type. */
        if (! is_a($this->accessTokenRepository, AccessTokenRepositoryInterface::class)) {
            throw OidcServerException::serverError(
                'Access token repository does not implement ' . AccessTokenRepositoryInterface::class,
            );
        }

        $accessToken = $this->accessTokenRepository->getNewToken(
            $client,
            $scopes,
            $userIdentifier,
            $authCodeId,
            $requestedClaims,
        );
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setPrivateKey($this->privateKey);

        while ($maxGenerationAttempts-- > 0) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);
                break;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $accessToken;
    }

    /**
     * Generate a new unique identifier.
     *
     * @param int $length
     * @throws OAuthServerException
     *
     * @return string
     */
    abstract protected function generateUniqueIdentifier($length = 40);
}
