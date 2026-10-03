<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Services;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Test\Module\oidc\integration\DatabaseContainers;

/**
 * Migrations against each supported database.
 *
 * Creating an index again is harmless on PostgreSQL and SQLite, which take CREATE INDEX IF NOT EXISTS,
 * but not on MySQL, which does not: there the migration looks the index up in the catalog first, and only
 * a MySQL server can show whether that lookup finds it.
 *
 * Runs under a table prefix of its own. The other integration tests migrate the same databases under
 * theirs, so under a shared prefix the first migrate() here would find everything done already, and a
 * failure after a version row is removed would leave their schema looking unmigrated.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Services\DatabaseMigrationTest
 * @see \SimpleSAML\Test\Module\oidc\integration\StatusList\StatusListStorageTest::testMigrationsAreIdempotent()
 */
#[CoversClass(DatabaseMigration::class)]
class DatabaseMigrationTest extends TestCase
{
    public static array $pgConfig;

    public static array $mysqlConfig;

    public static array $sqliteConfig;

    protected Database $database;


    /**
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        Configuration::setConfigDir(__DIR__ . '/../../../config');
        self::$pgConfig = DatabaseContainers::postgres();
        self::$mysqlConfig = DatabaseContainers::mysql();
        self::$sqliteConfig = DatabaseContainers::sqlite();
    }


    /**
     * A migration interrupted between creating the indexes on auth_code_id and recording its version.
     *
     * The version is written by a separate statement afterwards, and nothing rolls back the indexes
     * already created, so the next run runs the version again over indexes which are already there, and
     * would fail on MySQL with a duplicate key name if its catalog lookup missed them. Removing the version
     * row is exactly what that interruption leaves behind.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testAnInterruptedAuthCodeIndexMigrationCanBeRerun(string $database): void
    {
        $config = self::$$database;
        $config['database.prefix'] = 'migration_test_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();
        $this->assertTrue($migration->isMigrated());

        // The indexes are there, but as far as the versions table is concerned the migration never ran.
        $this->database->write(
            'DELETE FROM ' . $this->database->applyPrefix('oidc_migration_versions') . ' WHERE version = :version',
            ['version' => '20261003000001'],
        );
        $this->assertSame(
            ['version20261003000001'],
            array_values($migration->getNotImplementedVersions()),
        );

        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
        $this->assertSame([], $migration->getNotImplementedVersions());
    }


    /**
     * Points in time are stored as their wall clock in UTC, so no column holding one may convert it with the
     * connection's time zone. MySQL's TIMESTAMP does, and refuses a wall clock which a zone with daylight
     * saving time skips; version20261003000002 turned the older tables' columns into DATETIME. PostgreSQL's
     * TIMESTAMP has no time zone. SQLite stores what it is given, whatever a column is declared as.
     *
     * @throws \Exception
     */
    #[DataProvider('serverDatabases')]
    public function testStoresPointsInTimeInColumnsWhichIgnoreTheConnectionTimeZone(
        string $database,
        string $convertingType,
    ): void {
        $config = self::$$database;
        $config['database.prefix'] = 'migration_test_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));
        (new DatabaseMigration($this->database))->migrate();

        $schema = $database === 'mysqlConfig' ? 'DATABASE()' : 'CURRENT_SCHEMA()';
        $rows = $this->database->read(
            'SELECT table_name, column_name, data_type FROM information_schema.columns ' .
            "WHERE table_schema = $schema AND table_name LIKE 'migration_test_%' AND data_type LIKE '%time%'",
        )->fetchAll(PDO::FETCH_NUM);

        $types = [];
        foreach ($rows as [$table, $column, $type]) {
            $types["$table.$column"] = $type;
        }

        $this->assertArrayHasKey('migration_test_oidc_access_token.expires_at', $types);
        $this->assertNotContains($convertingType, $types);
    }


    /**
     * The servers, each with the column type which converts a point in time with the connection's time zone.
     *
     * @return array<string,array{string,string}>
     */
    public static function serverDatabases(): array
    {
        return [
            'PostgreSql' => ['pgConfig', 'timestamp with time zone'],
            'MySql' => ['mysqlConfig', 'timestamp'],
        ];
    }


    /**
     * @return array<string,array{string}>
     */
    public static function databaseToTest(): array
    {
        return DatabaseContainers::all();
    }
}
