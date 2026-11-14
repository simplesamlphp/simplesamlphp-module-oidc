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
     * The credential offer migration interrupted before its version was recorded: run again, it finds the table,
     * the four offer id columns and both indexes already there (the composite one on the status entries by its
     * catalog lookup on MySQL), and adds nothing twice.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testAnInterruptedCredentialOfferMigrationCanBeRerun(string $database): void
    {
        $config = self::$$database;
        $config['database.prefix'] = 'migration_test_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();

        $this->database->write(
            'DELETE FROM ' . $this->database->applyPrefix('oidc_migration_versions') . ' WHERE version = :version',
            ['version' => '20261111000001'],
        );
        $this->assertSame(
            ['version20261111000001'],
            array_values($migration->getNotImplementedVersions()),
        );

        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
        $this->assertSame([], $migration->getNotImplementedVersions());
    }


    /**
     * Reading the migration state of a database never migrated creates nothing. The Database Migrations screen
     * reads it on every visit, possibly as a database user without the CREATE privilege.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testReadsTheStateOfADatabaseNeverMigratedWithoutCreatingAnything(string $database): void
    {
        $config = self::$$database;
        $config['database.prefix'] = 'migration_fresh_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $migration = new DatabaseMigration($this->database);
        $this->assertFalse($migration->isMigrated());
        $this->assertNotSame([], $migration->getNotImplementedVersions());
        $this->assertSame([], $this->tableNamesLike('migration_fresh_%'));
    }


    /**
     * PostgreSQL folds the unquoted name of a table to lower case, so the versions table of a prefix with upper
     * case in it is found only by its folded name.
     *
     * @throws \Exception
     */
    #[DataProvider('databaseToTest')]
    public function testFindsTheVersionsUnderAPrefixWithUpperCase(string $database): void
    {
        $config = self::$$database;
        $config['database.prefix'] = 'Migration_Case_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
    }


    /**
     * Under the prefix in other letter case, the state reads as the server resolves the names of tables. PostgreSQL
     * folds unquoted names to lower case and SQLite matches them without regard to letter case, so there the tables
     * migrated are the prefix's tables too. MySQL, under the lower_case_table_names of 0 the test servers run with,
     * tells the names apart, so there the prefix is not migrated yet; MariaDB's information_schema does not tell them
     * apart, so a lookup going by it alone would take the table for there, and the SELECT after it would fail.
     *
     * @throws \Exception
     */
    #[DataProvider('caseOfNames')]
    public function testReadsTheVersionsUnderThePrefixInOtherLetterCaseAsTheServerResolvesThem(
        string $database,
        bool $isTheSameTable,
    ): void {
        $config = self::$$database;
        $config['database.prefix'] = 'Migration_Fold_';
        (new DatabaseMigration(Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'))))
            ->migrate();

        $config['database.prefix'] = 'MIGRATION_FOLD_';
        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $this->assertSame($isTheSameTable, (new DatabaseMigration($this->database))->isMigrated());
    }


    /**
     * A prefix can name a schema, which puts the module's tables there, and the versions table is found in it. The
     * MySQL database the tests use is called `database`, a reserved word no unquoted name can start with, so only
     * PostgreSQL is tried.
     *
     * @throws \Exception
     */
    public function testFindsTheVersionsUnderAPrefixNamingASchema(): void
    {
        $config = self::$pgConfig;
        $config['database.prefix'] = 'public.migration_schema_';

        $this->database = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));

        $migration = new DatabaseMigration($this->database);
        $migration->migrate();

        $this->assertTrue($migration->isMigrated());
    }


    /**
     * The migration state reads as a database user without DDL privileges, which the Database Migrations screen
     * advises removing once the migrations have run. PostgreSQL refuses such a user CREATE TABLE IF NOT EXISTS
     * even for a table which is already there, and reading the state used to issue one. MySQL and MariaDB refuse
     * it the same way, but the user the tests connect to MySQL as cannot create another.
     *
     * @throws \Exception
     */
    public function testReadsTheStateAsAUserWithoutDdlPrivileges(): void
    {
        $config = self::$pgConfig;
        $config['database.prefix'] = 'migration_test_';

        $owner = Database::getInstance(Configuration::loadFromArray($config, '', 'simplesaml'));
        (new DatabaseMigration($owner))->migrate();

        // Granted the reads and writes of day-to-day operation, and nothing else.
        $owner->write(
            "DO \$\$ BEGIN CREATE ROLE migration_reader LOGIN PASSWORD 'reader'; " .
            "EXCEPTION WHEN duplicate_object THEN NULL; END \$\$",
        );
        $owner->write('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO migration_reader');
        // No CREATE on the schema either, which PostgreSQL granted every role before version 15.
        $this->assertSame(
            [],
            $owner->read("SELECT 1 WHERE has_schema_privilege('migration_reader', 'public', 'CREATE')")->fetchAll(),
        );

        $readerConfig = ['database.username' => 'migration_reader', 'database.password' => 'reader'] + $config;
        $reader = Database::getInstance(Configuration::loadFromArray($readerConfig, '', 'simplesaml'));
        $this->assertTrue((new DatabaseMigration($reader))->isMigrated());

        // Nor before the migrations ran.
        $readerConfig['database.prefix'] = 'migration_fresh_';
        $reader = Database::getInstance(Configuration::loadFromArray($readerConfig, '', 'simplesaml'));
        $this->assertFalse((new DatabaseMigration($reader))->isMigrated());
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


    /**
     * Each database, with whether a table's name in other letter case names the same table.
     *
     * @return array<string,array{string,bool}>
     */
    public static function caseOfNames(): array
    {
        return [
            'PostgreSql' => ['pgConfig', true],
            'MySql' => ['mysqlConfig', false],
            'Sqlite' => ['sqliteConfig', true],
        ];
    }


    /**
     * The names of the tables of the database under test which match a LIKE pattern.
     *
     * @return string[]
     */
    protected function tableNamesLike(string $pattern): array
    {
        if ($this->database->getDriver() === 'sqlite') {
            $statement = "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE :pattern";
        } else {
            $schemaFunction = $this->database->getDriver() === 'pgsql' ? 'CURRENT_SCHEMA()' : 'DATABASE()';
            $statement = 'SELECT table_name FROM information_schema.tables ' .
            "WHERE table_schema = $schemaFunction AND table_name LIKE :pattern";
        }

        return $this->database->read($statement, ['pattern' => $pattern])->fetchAll(PDO::FETCH_COLUMN, 0);
    }
}
