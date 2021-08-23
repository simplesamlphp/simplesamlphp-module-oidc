<?php


namespace SimpleSAML\Module\oidc\Server\Grants\Traits;


use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\AbstractGrant;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;

/**
 * Trait IssueAccessTokenTrait
 * Certain parts of AbstractGrant are difficult to extend. This trait takes issueToken from AbstractGrant that we want
 * to change for our grants
 * @package SimpleSAML\Module\oidc\Server\Grants\Traits
 */
trait IssueAccessTokenTrait
{

    /**
     * @var AccessTokenRepositoryInterface
     */
    protected $accessTokenRepository;

    /**
     * @var CryptKey
     */
    protected $privateKey;

    /**
     * Issue an access token.
     *
     * @param DateInterval           $accessTokenTTL
     * @param ClientEntityInterface  $client
     * @param string|null            $userIdentifier
     * @param ScopeEntityInterface[] $scopes
     * @param string|null $authCodeId
     * @param array|null $requestedClaims Any requested claims
     * @return AccessTokenEntity
     * @throws OAuthServerException
     * @throws UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier,
        array $scopes = [],
        string $authCodeId = null,
        array $requstedClaims = null
    ): AccessTokenEntityInterface {
        $maxGenerationAttempts = AbstractGrant::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier, $authCodeId, $requstedClaims);
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
     *
     * @throws OAuthServerException
     *
     * @return string
     */
    abstract protected function generateUniqueIdentifier($length = 40);
}