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
    final public const TABLE_NAME = 'oidc_vci_issuer_state';

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
        return self::TABLE_NAME;
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

    public function revoke(string $value): void
    {
        $issuerState = $this->find($value);

        if ($issuerState === null) {
            return;
        }

        $issuerState->revoke();
        $this->update($issuerState);
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
     * Remove invalid issuer state entities (expired or revoked).
     * @return void
     */
    public function removeInvalid(): void
    {
        $stmt = sprintf(
            <<<EOS
            DELETE FROM %s
            WHERE
                expires_at < :expires_at OR
                is_revoked = :is_revoked
EOS
            ,
            $this->getTableName(),
        );

        $data = [
            'expires_at' => $this->helpers->dateTime()->getUtc()->format(DateFormatsEnum::DB_DATETIME->value),
            'is_revoked' => true,
        ];

        $this->database->write($stmt, $this->preparePdoState($data));
    }

    protected function preparePdoState(array $state): array
    {
        $isRevoked = (bool)($state['is_revoked'] ?? true);

        $state['is_revoked'] = [$isRevoked, PDO::PARAM_BOOL];

        return $state;
    }
}
