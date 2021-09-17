<?php

namespace SimpleSAML\Module\oidc\Store;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class DbLogoutTicketStore implements LogoutTicketStoreInterface
{
    public const TABLE_NAME = 'oidc_logout_ticket';

    protected Database $database;

    /**
     * TTL in seconds, used for ticket expiration.
     */
    protected int $ttl;

    public function __construct(int $ttl = 60)
    {
        $this->database = Database::getInstance();
    }

    public function add(string $sid): void
    {
        $stmt = sprintf(
            "INSERT INTO %s (sid) VALUES (:sid)",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            [$sid]
        );
    }

    public function delete(string $sid): void
    {
        // TODO
    }

    public function getAll(): array
    {
        // TODO
    }

    protected function deleteExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE expires_at < :expiration",
            [
                'expiration' => TimestampGenerator::utc()
                    ->add(new \DateInterval('PT' . $this->ttl . 'S'))
                    ->format('Y-m-d H:i:s'),
            ]
        );
    }
    /**
     * @return string
     */
    public function getTableName(): string
    {
        return $this->database->applyPrefix(self::TABLE_NAME);
    }
}
