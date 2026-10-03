<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface as OAuth2RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use PDO;
use RuntimeException;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\Interfaces\RefreshTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class RefreshTokenRepository extends AbstractDatabaseRepository implements RefreshTokenRepositoryInterface
{
    final public const string TABLE_NAME = 'oidc_refresh_token';


    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly AccessTokenRepository $accessTokenRepository,
        protected readonly RefreshTokenEntityFactory $refreshTokenEntityFactory,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }


    /**
     * @return string
     */
    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }


    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        throw new RuntimeException('Not implemented. Use RefreshTokenEntityFactory instead.');
    }


    /**
     * {@inheritdoc}
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function persistNewRefreshToken(OAuth2RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if (!$refreshTokenEntity instanceof RefreshTokenEntity) {
            throw OAuthServerException::invalidRefreshToken();
        }

        $stmt = sprintf(
            "INSERT INTO %s (id, expires_at, access_token_id, is_revoked, auth_code_id) "
                . "VALUES (:id, :expires_at, :access_token_id, :is_revoked, :auth_code_id)",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($refreshTokenEntity->getState()),
        );

        $this->protocolCache?->set(
            $refreshTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $refreshTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($refreshTokenEntity->getIdentifier()),
        );
    }


    /**
     * Find Refresh Token by id.
     *
     * Read from the primary: the refresh token grant refuses a refresh token by its revocation (one already
     * exchanged, say), which a database secondary that has not caught up yet may not have. A copy read here is
     * cached for the token's remaining lifetime, so a stale one would outlast the lag.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function findById(string $tokenId): ?RefreshTokenEntityInterface
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

        $accessToken = $this->accessTokenRepository->findById((string)$data['access_token_id']);

        if (!$accessToken instanceof AccessTokenEntity) {
            // The token's access token is gone (with its user or its client, whose deletion the database cascades),
            // and the refresh token's row went with it: what answered here is a copy of the row in the protocol
            // cache, dropped with the access token.
            $this->protocolCache?->delete($this->getCacheKey($tokenId));
            return null;
        }

        $data['access_token'] = $accessToken;

        $refreshTokenEntity = $this->refreshTokenEntityFactory->fromState($data);

        $this->protocolCache?->set(
            $refreshTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $refreshTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($refreshTokenEntity->getIdentifier()),
        );

        return $refreshTokenEntity;
    }


    /**
     * {@inheritdoc}
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function revokeRefreshToken(string $tokenId): void
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new TokenNotFoundException("RefreshToken not found: $tokenId");
        }

        $refreshToken->revoke();
        $this->update($refreshToken);
    }


    /**
     * Revoke every refresh token issued for an authorization code. They are found on the primary: the token endpoint
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
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $refreshToken = $this->findById($tokenId);

        if (!$refreshToken) {
            throw new TokenNotFoundException("RefreshToken not found: $tokenId");
        }

        return $refreshToken->isRevoked();
    }


    /**
     * Removes expired refresh tokens.
     * @throws \Exception
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :now",
            [
                'now' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value),
            ],
        );
    }


    private function update(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        $stmt = sprintf(
            "UPDATE %s SET expires_at = :expires_at, access_token_id = :access_token_id, is_revoked = :is_revoked, "
                . "auth_code_id = :auth_code_id WHERE id = :id",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($refreshTokenEntity->getState()),
        );

        $this->protocolCache?->set(
            $refreshTokenEntity->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $refreshTokenEntity->getExpiryDateTime()->getTimestamp(),
            ),
            $this->getCacheKey($refreshTokenEntity->getIdentifier()),
        );
    }


    protected function preparePdoState(array $state): array
    {
        $isRevoked = (bool)($state['is_revoked'] ?? true);

        $state['is_revoked'] = [$isRevoked, PDO::PARAM_BOOL];

        return $state;
    }
}
