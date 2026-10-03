<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * Migrations on SQLite.
 *
 * Runs on a database of its own, over a connection and a table prefix no other test uses, so the schema
 * it migrates, and the versions it takes back out, are its own and not the repository tests'.
 *
 * @see \SimpleSAML\Test\Module\oidc\integration\Services\DatabaseMigrationTest for every supported database
 */
#[CoversClass(DatabaseMigration::class)]
class DatabaseMigrationTest extends TestCase
{
    protected const string AUTH_CODE_INDEX_VERSION = '20261003000001';

    protected const string ORPHANED_ORIGINS_VERSION = '20261003000003';


    protected Database $database;


    protected function setUp(): void
    {
        $this->database = Database::getInstance(Configuration::loadFromArray([
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'migration_test_',
            'database.persistent' => false,
            'database.secondaries' => [],
        ]));
    }


    /**
     * @return array<string,array{string}>
     */
    public static function tokenTables(): array
    {
        return [
            'access tokens' => [AccessTokenRepository::TABLE_NAME],
            'refresh tokens' => [RefreshTokenRepository::TABLE_NAME],
        ];
    }


    /**
     * The token endpoint revokes every token issued for an authorization code presented again, and finds
     * them by the code. That lookup goes through an index rather than reading the whole table.
     *
     * @throws \Exception
     */
    #[DataProvider('tokenTables')]
    public function testFindsTheTokensOfAnAuthorizationCodeThroughAnIndex(string $table): void
    {
        (new DatabaseMigration($this->database))->migrate();

        $this->assertMatchesRegularExpression(
            '/\bUSING INDEX \S+ \(auth_code_id=\?\)/',
            $this->queryPlanOfALookupByAuthCode($table),
        );
    }


    /**
     * A migration interrupted between creating the indexes and recording its version.
     *
     * The version is written by a separate statement afterwards, and nothing rolls back the indexes
     * already created, so the next run runs the version again over indexes which are already there.
     * Removing the version row is exactly what that interruption leaves behind.
     *
     * @throws \Exception
     */
    public function testAnInterruptedAuthCodeIndexMigrationCanBeRerun(): void
    {
        $migration = new DatabaseMigration($this->database);
        $migration->migrate();
        $this->assertTrue($migration->isMigrated());

        $this->database->write(
            'DELETE FROM ' . $this->database->applyPrefix('oidc_migration_versions') . ' WHERE version = :version',
            ['version' => self::AUTH_CODE_INDEX_VERSION],
        );
        $this->assertSame(
            ['version' . self::AUTH_CODE_INDEX_VERSION],
            array_values($migration->getNotImplementedVersions()),
        );

        $migration->migrate();

        $this->assertTrue($migration->isMigrated());

        foreach (self::tokenTables() as [$table]) {
            $this->assertMatchesRegularExpression(
                '/\bUSING INDEX \S+ \(auth_code_id=\?\)/',
                $this->queryPlanOfALookupByAuthCode($table),
            );
        }
    }


    /**
     * SQLite enforced no foreign key, so a client deleted before this version left its allowed origins behind, and
     * a CORS request from one of them was still allowed.
     *
     * @throws \Exception
     */
    public function testDeletesTheAllowedOriginsOfClientsWhichNoLongerExist(): void
    {
        $migration = new DatabaseMigration($this->database);
        $migration->migrate();

        $clientTableName = $this->database->applyPrefix(ClientRepository::TABLE_NAME);
        $allowedOriginTableName = $this->database->applyPrefix(AllowedOriginRepository::TABLE_NAME);
        $this->database->write(
            "INSERT INTO $clientTableName (id, secret, name, description, redirect_uri, scopes) " .
            "VALUES ('remaining-client', 'secret', 'Remaining', 'A client still there', '[]', '[]')",
        );
        $this->database->write(
            "INSERT INTO $allowedOriginTableName (client_id, origin) VALUES " .
            "('remaining-client', 'https://remaining.example.org'), ('deleted-client', 'https://deleted.example.org')",
        );
        $this->database->write(
            'DELETE FROM ' . $this->database->applyPrefix('oidc_migration_versions') . ' WHERE version = :version',
            ['version' => self::ORPHANED_ORIGINS_VERSION],
        );

        $migration->migrate();

        $this->assertSame(
            [['client_id' => 'remaining-client', 'origin' => 'https://remaining.example.org']],
            $this->database->read("SELECT client_id, origin FROM $allowedOriginTableName")->fetchAll(PDO::FETCH_ASSOC),
        );
    }


    /**
     * How SQLite would answer the lookup revokeByAuthCodeId() makes, one line per step.
     *
     * @throws \Exception
     */
    protected function queryPlanOfALookupByAuthCode(string $table): string
    {
        $rows = $this->database->read(
            'EXPLAIN QUERY PLAN SELECT * FROM ' . $this->database->applyPrefix($table) .
            ' WHERE auth_code_id = :auth_code_id',
            ['auth_code_id' => 'an-auth-code-id'],
        )->fetchAll(PDO::FETCH_ASSOC);

        return implode("\n", array_column($rows, 'detail'));
    }
}
