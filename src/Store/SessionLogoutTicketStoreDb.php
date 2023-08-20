<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Store;

use DateInterval;
use Exception;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class SessionLogoutTicketStoreDb implements SessionLogoutTicketStoreInterface
{
    public const TABLE_NAME = 'oidc_session_logout_ticket';

    protected Database $database;

    /**
     * TTL in seconds, used for ticket expiration.
     */
    protected int $ttl;

    public function __construct(?Database $database = null, int $ttl = 60)
    {
        $this->database = $database ?? Database::getInstance();
        $this->ttl = $ttl >= 0 ? $ttl : 0;
    }

    public function add(string $sid): void
    {
        $stmt = sprintf(
            "INSERT INTO %s (sid) VALUES (:sid)",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            ['sid' => $sid]
        );
    }

    /**
     * @throws Exception
     */
    public function delete(string $sid): void
    {
        $this->deleteExpired();

        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE sid = :sid",
            ['sid' => $sid,]
        );
    }

    /**
     * @inheritDoc
     * @throws Exception
     */
    public function deleteMultiple(array $sids): void
    {
        $this->deleteExpired();

        if (empty($sids)) {
            return;
        }

        $stmt = "DELETE FROM {$this->getTableName()} WHERE sid IN (";

        $params = [];
        foreach ($sids as $idx => $sid) {
            if ($idx > 0) {
                $stmt .= ',';
            }
            $paramPlaceholder = 'sid_' . $idx;
            $params[$paramPlaceholder] = $sid;
            $stmt .= ":$paramPlaceholder";
        }
        $stmt .= ")";

        $this->database->write($stmt, $params);
    }

    /**
     * @throws Exception
     */
    public function getAll(): array
    {
        $this->deleteExpired();
        return $this->database->read("SELECT * FROM {$this->getTableName()}")->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @throws Exception
     */
    protected function deleteExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE created_at <= :expiration",
            [
                'expiration' => TimestampGenerator::utc()
                    ->sub(new DateInterval('PT' . $this->ttl . 'S'))
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
