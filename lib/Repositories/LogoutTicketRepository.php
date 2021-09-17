<?php

namespace SimpleSAML\Module\oidc\Repositories;

use SimpleSAML\Database;

class LogoutTicketRepository
{
    public const TABLE_NAME = 'oidc_logout_ticket';

    protected static $database;

    protected static $isInitialized;

    public function __construct()
    {
        self::init();
    }

    public static function init(): void
    {
        if (self::$isInitialized) {
            return;
        }

        self::$database = Database::getInstance();

        self::$isInitialized = true;
    }

    public static function add(string $sid): void
    {
        self::init();
    }

    public static function delete(string $sid): void
    {
        self::init();
    }

    public static function getAll(): void
    {
        self::init();
    }

    /**
     * @return string
     */
    public function getTableName(): string
    {
        return self::$database->applyPrefix(self::TABLE_NAME);
    }
}
