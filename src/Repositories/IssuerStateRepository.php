<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

class IssuerStateRepository extends AbstractDatabaseRepository
{
    final public const string TABLE_NAME = 'oidc_vci_issuer_state';


    public function __construct(
        ModuleConfig $moduleConfig,
        Database $database,
        ?ProtocolCache $protocolCache,
        protected readonly IssuerStateEntityFactory $issuerStateEntityFactory,
        protected readonly Helpers $helpers,
    ) {
        parent::__construct($moduleConfig, $database, $protocolCache);
    }


    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }


    public function find(string $value): ?IssuerStateEntity
    {
        /** @var ?array $data */
        $data = $this->protocolCache?->get(null, $this->getCacheKey($value));

        if (!is_array($data)) {
            $stmt = $this->database->read(
                "SELECT * FROM {$this->getTableName()} WHERE value = :value",
                [
                    'value' => $value,
                ],
            );

            if (empty($rows = $stmt->fetchAll())) {
                return null;
            }

            /** @var array $data */
            $data = current($rows);
        }

        $issuerState = $this->issuerStateEntityFactory->fromState($data);

        $this->protocolCache?->set(
            $issuerState->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $issuerState->getExpirestAt()->getTimestamp(),
            ),
            $this->getCacheKey($issuerState->getValue()),
        );

        return $issuerState;
    }


    public function findValid(string $value): ?IssuerStateEntity
    {
        $issuerState = $this->find($value);

        if ($issuerState === null) {
            return null;
        }

        if ($issuerState->getExpirestAt() < $this->helpers->dateTime()->getUtc()) {
            return null;
        }

        if ($issuerState->isRevoked()) {
            return null;
        }

        return $issuerState;
    }


    /**
     * Atomically spend an issuer state which is still valid. Returns true only for the call which spent it.
     *
     * A Credential Offer's issuer state is redeemed once, when the authorization code carrying it is exchanged
     * for an access token. The database is the source of truth for that: a conditional update lets only one
     * request change a valid state to revoked, even when concurrent requests read the same cached entity.
     */
    public function consume(string $value): bool
    {
        $stmt = "UPDATE {$this->getTableName()} SET is_revoked = :revoked " .
        "WHERE value = :value AND is_revoked = :not_revoked AND expires_at >= :now";

        $affected = $this->database->write(
            $stmt,
            [
                'value' => $value,
                'revoked' => [true, PDO::PARAM_BOOL],
                'not_revoked' => [false, PDO::PARAM_BOOL],
                'now' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value),
            ],
        );

        // Never let a stale cached entity report the state as still valid.
        $this->protocolCache?->delete($this->getCacheKey($value));

        return $affected === 1;
    }


    /**
     * Give back an issuer state which consume() spent for a token that was then not issued, so that the wallet
     * can retry the code it holds. Only a spent state is changed; one which has expired meanwhile stays
     * unusable all the same, since findValid() and consume() check the expiry as well.
     */
    public function release(string $value): void
    {
        $stmt = "UPDATE {$this->getTableName()} SET is_revoked = :not_revoked " .
        "WHERE value = :value AND is_revoked = :revoked";

        $this->database->write(
            $stmt,
            [
                'value' => $value,
                'revoked' => [true, PDO::PARAM_BOOL],
                'not_revoked' => [false, PDO::PARAM_BOOL],
            ],
        );

        $this->protocolCache?->delete($this->getCacheKey($value));
    }


    public function update(IssuerStateEntity $issuerState): void
    {
        $stmt = sprintf(
            <<<EOS
            UPDATE %s
            SET
                created_at = :created_at,
                expires_at = :expires_at,
                is_revoked = :is_revoked
            WHERE
                value = :value
EOS
            ,
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($issuerState->getState()),
        );

        $this->protocolCache?->set(
            $issuerState->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $issuerState->getExpirestAt()->getTimestamp(),
            ),
            $this->getCacheKey($issuerState->getValue()),
        );
    }


    public function persist(IssuerStateEntity $issuerState): void
    {
        $stmt = sprintf(
            <<<EOS
            INSERT INTO %s
            (value, created_at, expires_at, is_revoked)
            VALUES
            (:value, :created_at, :expires_at, :is_revoked)
EOS
            ,
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            $this->preparePdoState($issuerState->getState()),
        );

        $this->protocolCache?->set(
            $issuerState->getState(),
            $this->helpers->dateTime()->getSecondsToExpirationTime(
                $issuerState->getExpirestAt()->getTimestamp(),
            ),
            $this->getCacheKey($issuerState->getValue()),
        );
    }


    /**
     * Remove expired issuer states. A spent one is kept until it expires, so that a redemption whose tokens
     * could not be issued still finds it to give back (AuthCodeGrant, release()); it can not be redeemed in
     * the meantime, since consume() and findValid() refuse a spent state.
     */
    public function removeExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :expires_at",
            [
                'expires_at' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value),
            ],
        );
    }


    protected function preparePdoState(array $state): array
    {
        $isRevoked = (bool)($state['is_revoked'] ?? true);

        $state['is_revoked'] = [$isRevoked, PDO::PARAM_BOOL];

        return $state;
    }
}
