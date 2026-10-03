<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class AccessTokenRepository extends AbstractDatabaseRepository implements AccessTokenRepositoryInterface
{
    final public const string TABLE_NAME = 'oidc_access_token';


    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly ClientRepository $clientRepository,
        protected readonly AccessTokenEntityFactory $accessTokenEntityFactory,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }


    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }


    /**
     * {@inheritdoc}
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function getNewToken(
        OAuth2ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
        ?array $requestedClaims = null,
        ?string $id = null,
        ?DateTimeImmutable $expiryDateTime = null,
    ): AccessTokenEntityInterface {
        if (empty($userIdentifier)) {
            $userIdentifier = null;
        }
        if (
            is_null($id) ||
            is_null($expiryDateTime)
        ) {
            throw OidcServerException::serverError('Invalid access token data provided.');
        }
        return $this->accessTokenEntityFactory->fromData(
            $id,
            $clientEntity,
            $scopes,
            $expiryDateTime,
            $userIdentifier,
            $authCodeId,
            $requestedClaims,
        );
    }


    /**
     * {@inheritdoc}
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     */
    public function persistNewAccessToken(OAuth2AccessTokenEntityInterface $accessTokenEntity): void
    {
        if (!($accessTokenEntity instanceof AccessTokenEntity)) {
            throw new Error('Invalid AccessTokenEntity');
        }

        $stmt = sprintf(
            "INSERT INTO %s (
                id,
                scopes,
                expires_at,
                user_id,
                client_id,
                is_revoked,
                auth_code_id,
                requested_claims,
                flow_type,
                authorization_details,
                bound_client_id,
                bound_redirect_uri,
                issuer_state
                ) "
            . "VALUES (
                          :id,
                          :scopes,
                          :expires_at,
                          :user_id,
                          :client_id,
                          :is_revoked,
                          :auth_code_id,
                          :requested_claims,
                          :flow_type,
                          :authorization_details,
                          :bound_client_id,
                          :bound_redirect_uri,
                          :issuer_state
                          )",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($accessTokenEntity->getState()),
        );

        $this->protocolCache?->set(
            $accessTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $accessTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($accessTokenEntity->getIdentifier()),
        );
    }


    /**
     * Find Access Token by id.
     *
     * Read from the primary: a resource endpoint may look a token up moments after the token endpoint issued it,
     * and accepts it only if it is not revoked, neither of which a database secondary that has not caught up yet
     * may have. A copy read here is cached for the token's remaining lifetime, so a stale one would outlast the lag.
     *
     * @throws \Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function findById(string $tokenId): ?AccessTokenEntity
    {
        /** @var ?array $data */
        $data = $this->protocolCache?->get(null, $this->getCacheKey($tokenId));

        if (!is_array($data)) {
            $stmt = $this->database->readPrimary(
                "SELECT * FROM {$this->getTableName()} WHERE id = :id",
                [
                    'id' => $tokenId,
                ],
            );

            if (empty($rows = $stmt->fetchAll())) {
                return null;
            }

            /** @var array $data */
            $data = current($rows);
        }

        $client = $this->clientRepository->findById((string)$data['client_id']);

        if (!$client instanceof ClientEntityInterface) {
            // The token's client is gone, and the token's row went with it (the database cascades the client's
            // deletion): what answered here is a copy of the row in the protocol cache, dropped with the client.
            $this->protocolCache?->delete($this->getCacheKey($tokenId));
            return null;
        }

        $data['client'] = $client;

        $accessTokenEntity = $this->accessTokenEntityFactory->fromState($data);

        $this->protocolCache?->set(
            $accessTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $accessTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($accessTokenEntity->getIdentifier()),
        );

        return $accessTokenEntity;
    }


    /**
     * {@inheritdoc}
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function revokeAccessToken(string $tokenId): void
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken instanceof AccessTokenEntity) {
            throw new TokenNotFoundException("AccessToken not found: $tokenId");
        }

        $accessToken->revoke();
        $this->update($accessToken);
    }


    /**
     * Revoke every access token issued for an authorization code. They are found on the primary: the token endpoint
     * may revoke them moments after issuing them, when a code is replayed right away, and when the rest of its
     * own response fails (AuthCodeGrant gives a Credential Offer back only once they are revoked), and a
     * secondary which has not caught up yet would not have them. Each is revoked by its primary key, since
     * auth_code_id has no index, and an UPDATE by it would scan the table (on InnoDB, locking every row it
     * scans). No token is loaded, as loading one may read such a secondary. Each revoked row is then cached in
     * place of any copy, and also where there was none: otherwise the next lookup could read a secondary which
     * does not have the revocation yet, and cache the token again as valid. A token which has already expired
     * is dropped from the cache instead (its TTL is not positive), and is refused for its expiry anyway.
     *
     * @throws \Exception
     */
    public function revokeByAuthCodeId(string $authCodeId): void
    {
        $rows = $this->database->readPrimary(
            "SELECT * FROM {$this->getTableName()} WHERE auth_code_id = :auth_code_id",
            ['auth_code_id' => $authCodeId],
        )->fetchAll(PDO::FETCH_ASSOC);

        /** @var array $row */
        foreach ($rows as $row) {
            $this->database->write(
                "UPDATE {$this->getTableName()} SET is_revoked = :revoked WHERE id = :id",
                ['revoked' => [true, PDO::PARAM_BOOL], 'id' => (string)$row['id']],
            );

            $row['is_revoked'] = true;

            $this->protocolCache?->set(
                $row,
                $this->helpers->dateTime()->getSecondsToExpirationTime(
                    $this->helpers->dateTime()->getUtc((string)$row['expires_at'])->getTimestamp(),
                ),
                $this->getCacheKey((string)$row['id']),
            );
        }
    }


    /**
     * {@inheritdoc}
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $accessToken = $this->findById($tokenId);

        if (!$accessToken) {
            throw new TokenNotFoundException("AccessToken not found: $tokenId");
        }

        return $accessToken->isRevoked();
    }


    /**
     * Removes expired access tokens.
     * @throws \Exception
     */
    public function removeExpired(): void
    {
        $accessTokenTableName = $this->getTableName();
        $refreshTokenTableName = $this->database->applyPrefix(RefreshTokenRepository::TABLE_NAME);
        $now = $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value);

        // Delete expired access tokens, but only if the corresponding refresh token is also expired.
        $this->database->write(
            "DELETE FROM $accessTokenTableName WHERE expires_at < :now AND
                NOT EXISTS (
                    SELECT 1 FROM {$refreshTokenTableName}
                    WHERE $accessTokenTableName.id = $refreshTokenTableName.access_token_id AND expires_at > :now2
                )",
            [
                'now' => $now,
                'now2' => $now,
            ],
        );
    }


    /**
     * @throws \JsonException
     */
    private function update(AccessTokenEntity $accessTokenEntity): void
    {
        $stmt = sprintf(
            "UPDATE %s SET scopes = :scopes, expires_at = :expires_at, user_id = :user_id, "
                . "client_id = :client_id, is_revoked = :is_revoked, auth_code_id = :auth_code_id, "
                . "requested_claims = :requested_claims, flow_type = :flow_type, " .
            "authorization_details = :authorization_details, bound_client_id = :bound_client_id, " .
            "bound_redirect_uri = :bound_redirect_uri, issuer_state = :issuer_state WHERE id = :id",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($accessTokenEntity->getState()),
        );

        $this->protocolCache?->set(
            $accessTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $accessTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($accessTokenEntity->getIdentifier()),
        );
    }


    protected function preparePdoState(array $state): array
    {
        $isRevoked = (bool)($state['is_revoked'] ?? true);
        $state['is_revoked'] = [$isRevoked, PDO::PARAM_BOOL];

        return $state;
    }
}
