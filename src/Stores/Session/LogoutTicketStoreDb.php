<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Stores\Session;

use DateInterval;
use PDO;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Helpers;

class LogoutTicketStoreDb implements LogoutTicketStoreInterface
{
    final public const TABLE_NAME = 'oidc_session_logout_ticket';

    protected Database $database;

    /**
     * TTL in seconds, used for ticket expiration.
     */
    protected int $ttl;

    public function __construct(
        ?Database $database = null,
        int $ttl = 60,
        protected readonly Helpers $helpers = new Helpers(),
    ) {
        $this->database = $database ?? Database::getInstance();
        $this->ttl = max($ttl, 0);
    }

    public function add(string $sid): void
    {
        $stmt = sprintf(
            "INSERT INTO %s (sid) VALUES (:sid)",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            ['sid' => $sid],
        );
    }

    /**
     * @throws \Exception
     */
    public function delete(string $sid): void
    {
        $this->deleteExpired();

        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE sid = :sid",
            ['sid' => $sid],
        );
    }

    /**
     * @inheritDoc
     * @throws \Exception
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
     * @throws \Exception
     */
    public function getAll(): array
    {
        $this->deleteExpired();
        return $this->database->read("SELECT * FROM {$this->getTableName()}")->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @throws \Exception
     */
    protected function deleteExpired(): void
    {
        $this->database->write(
            "DELETE FROM {$this->getTableName()} WHERE created_at <= :expiration",
            [
                'expiration' => $this->helpers->dateTime()->getUtc()
                    ->sub(new DateInterval('PT' . $this->ttl . 'S'))
                    ->format(DateFormatsEnum::DB_DATETIME->value),
            ],
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
