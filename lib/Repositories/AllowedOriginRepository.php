<?php

namespace SimpleSAML\Module\oidc\Repositories;

class AllowedOriginRepository extends AbstractDatabaseRepository
{
    public const TABLE_NAME = 'oidc_allowed_origin';

    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }

    public function setClientAllowedOrigins(string $clientId, array $origins): void
    {
        $this->deleteClientAllowedOrigins($clientId);

        if (empty($origins)) {
            return;
        }

        // Filter duplicates


    }

    public function deleteClientAllowedOrigins(string $clientId): void
    {

    }
}
