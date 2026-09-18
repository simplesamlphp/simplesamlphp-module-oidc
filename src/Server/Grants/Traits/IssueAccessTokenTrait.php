<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Grants\Traits;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;

/**
 * Trait IssueAccessTokenTrait
 * Certain parts of AbstractGrant are difficult to extend. This trait takes issueToken from AbstractGrant that we want
 * to change for our grants
 * @package SimpleSAML\Module\oidc\Server\Grants\Traits
 */
trait IssueAccessTokenTrait
{
    protected AccessTokenEntityFactory $accessTokenEntityFactory;

    protected SubjectResolver $subjectResolver;

    protected AccessTokenClaimsResolver $accessTokenClaimsResolver;


    /**
     * Issue an access token.
     *
     * The token's subject and user claims are resolved here, once, from the user record as it is now, and
     * travel with the token (AccessTokenEntity::getSubject(), getUserClaims()): the ID token issued alongside
     * and the refresh token payload take the subject from the entity rather than resolving it again. A caller
     * which already holds the user entity passes it; for the others it is looked up. A caller redeeming a
     * refresh token passes the subject its payload carries, so the subject stays what it was when the user
     * authenticated (OpenID Connect Core 1.0 section 12.2) and only the claims are read afresh.
     *
     * Nothing is resolved when there is no user (a pre-authorized code without one). A user record which is gone
     * leaves the token with the internal identifier as its subject and without user claims; minting does not fail
     * on it.
     *
     * @param int|string|null $userIdentifier
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     * @param array|null $requestedClaims Any requested claims
     * @param \SimpleSAML\Module\oidc\Entities\UserEntity|null $user The user record, when the caller holds it.
     * @param string|null $subject The subject to carry instead of resolving one (refresh token grant).
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        $userIdentifier = null,
        array $scopes = [],
        ?string $authCodeId = null,
        ?array $requestedClaims = null,
        ?FlowTypeEnum $flowTypeEnum = null,
        ?array $authorizationDetails = null,
        ?string $boundClientId = null,
        ?string $boundRedirectUri = null,
        ?string $issuerState = null,
        ?UserEntity $user = null,
        ?string $subject = null,
    ): AccessTokenEntityInterface {
        $maxGenerationAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;

        /** Since we are using our own repository interface, check for proper type. */
        if (! is_a($this->accessTokenRepository, AccessTokenRepositoryInterface::class)) {
            throw OidcServerException::serverError(
                'Access token repository does not implement ' . AccessTokenRepositoryInterface::class,
            );
        }

        // The user repository slot is league's (AbstractGrant, for its password grant); the lookup needs the
        // module's own, which the grant constructors set.
        if (! $this->userRepository instanceof UserRepository) {
            throw OidcServerException::serverError('User repository is not ' . UserRepository::class);
        }

        // The entity treats an empty identifier as no user; so does the resolution below.
        $userIdentifier = is_scalar($userIdentifier) && (string)$userIdentifier !== '' ? (string)$userIdentifier : null;
        $userClaims = [];

        if ($userIdentifier !== null) {
            $user ??= $this->userRepository->getUserEntityByIdentifier($userIdentifier);

            if ($user instanceof UserEntity) {
                $subject ??= $this->subjectResolver->resolve($user);
                $userClaims = $this->accessTokenClaimsResolver->resolve($user, $scopes);
            } else {
                $this->loggerService->warning(
                    'Access token issued for a user whose record is not in storage: it carries no user claims, and ' .
                    'its subject is the one carried over (refresh) or else the internal user identifier.',
                    ['client_id' => $client->getIdentifier(), 'user_id' => $userIdentifier],
                );
                $subject ??= $userIdentifier;
            }
        }

        while ($maxGenerationAttempts-- > 0) {
            try {
                $accessToken = $this->accessTokenEntityFactory->fromData(
                    $this->generateUniqueIdentifier(),
                    $client,
                    $scopes,
                    (new DateTimeImmutable())->add($accessTokenTTL),
                    $userIdentifier,
                    $authCodeId,
                    $requestedClaims,
                    flowTypeEnum: $flowTypeEnum,
                    authorizationDetails: $authorizationDetails,
                    boundClientId: $boundClientId,
                    boundRedirectUri: $boundRedirectUri,
                    issuerState: $issuerState,
                    subject: $subject,
                    userClaims: $userClaims,
                );
                $this->accessTokenRepository->persistNewAccessToken($accessToken);
                return $accessToken;
            } catch (UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxGenerationAttempts === 0) {
                    throw $e;
                }
            }
        }

        throw OidcServerException::serverError('Unable to issue Access Token.');
    }


    /**
     * Generate a new unique identifier.
     *
     * @param int $length
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     *
     * @return string
     */
    abstract protected function generateUniqueIdentifier(int $length = 40): string;
}
