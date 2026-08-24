<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration;

use Exception;
use PDO;
use Testcontainers\Container\MySQLContainer;
use Testcontainers\Container\PostgresContainer;
use Testcontainers\Wait\WaitForHealthCheck;
use Testcontainers\Wait\WaitForLog;

/**
 * The databases the integration tests run against, started once per process.
 *
 * Each test class used to start its own containers from setUpBeforeClass(), which was fine while there
 * was one such class and became a source of intermittent failures as soon as there were two: four
 * containers competing for ports and for the resources of a machine which has just torn two down.
 * Statics outlive a class here, so memoising means the containers are started once however many test
 * classes ask for them.
 *
 * Nothing starts when the environment already points at running databases, which is how CI supplies
 * them: set HOSTADDRESS, HOSTPORT_MY and HOSTPORT_PG and no container is created at all.
 *
 * Not named *Test, so that PHPUnit does not try to run it.
 */
final class DatabaseContainers
{
    /** @var array<string,mixed>|null */
    private static ?array $postgresConfig = null;

    /** @var array<string,mixed>|null */
    private static ?array $mysqlConfig = null;

    private static ?string $containerAddress = null;

    private static ?string $mysqlPort = null;

    private static ?string $postgresPort = null;

    private static bool $isEnvironmentResolved = false;


    private function __construct()
    {
    }


    /**
     * @return array<string,mixed>
     * @throws \Exception
     */
    public static function postgres(): array
    {
        self::resolveEnvironment();

        return self::$postgresConfig ??= self::startPostgres();
    }


    /**
     * @return array<string,mixed>
     * @throws \Exception
     */
    public static function mysql(): array
    {
        self::resolveEnvironment();

        return self::$mysqlConfig ??= self::startMysql();
    }


    /**
     * @return array<string,mixed>
     */
    public static function sqlite(): array
    {
        return [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
        ];
    }


    /**
     * @return array<string,array{string}>
     */
    public static function all(): array
    {
        return [
            'PostgreSql' => ['pgConfig'],
            'MySql' => ['mysqlConfig'],
            'Sqlite' => ['sqliteConfig'],
        ];
    }


    private static function resolveEnvironment(): void
    {
        if (self::$isEnvironmentResolved) {
            return;
        }

        self::$containerAddress = getenv('HOSTADDRESS') ?: null;
        self::$mysqlPort = getenv('HOSTPORT_MY') ?: null;
        self::$postgresPort = getenv('HOSTPORT_PG') ?: null;

        // Docker on macOS needs the mapped port on localhost rather than the container address.
        if (in_array(PHP_OS_FAMILY, ['Darwin', 'Linux'], true) && getenv('HOSTADDRESS') === false) {
            self::$containerAddress = '127.0.0.1';
        } else {
            self::$mysqlPort ??= '3306';
            self::$postgresPort ??= '5432';
        }

        self::$isEnvironmentResolved = true;
    }


    /**
     * @return array<string,mixed>
     * @throws \Exception
     */
    private static function startPostgres(): array
    {
        $container = PostgresContainer::make('15.0', 'password');
        $container->withPostgresDatabase('database');
        $container->withPostgresUser('username');
        $hostPort = self::$postgresPort ?: self::findFreePort();
        $container->withPort($hostPort, '5432');

        $container->run();
        $container->withWait(new WaitForHealthCheck());
        $container->withWait(new WaitForLog('Ready to accept connections'));

        $hostAddress = self::$containerAddress ?: $container->getAddress();

        return [
            'database.dsn' => sprintf('pgsql:host=%s;port=%s;dbname=database', $hostAddress, $hostPort),
            'database.username' => 'username',
            'database.password' => 'password',
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
            'database.driver_options' => [PDO::ATTR_TIMEOUT => 2],
        ];
    }


    /**
     * @return array<string,mixed>
     * @throws \Exception
     */
    private static function startMysql(): array
    {
        $container = MySQLContainer::make('8.0');
        $container->withMySQLDatabase('database');
        $container->withMySQLUser('username', 'password');
        $hostPort = self::$mysqlPort ?: self::findFreePort();
        $container->withPort($hostPort, '3306');

        $container->run();
        $container->withWait(new WaitForHealthCheck());
        $container->withWait(new WaitForLog('Ready to accept connections'));

        $hostAddress = self::$containerAddress ?: $container->getAddress();

        if ($hostAddress === 'localhost') {
            //phpcs:ignore Generic.Files.LineLength.TooLong
            throw new Exception('To connect to localhost with mysql use IP 127.0.0.1, otherwise mysql tries to use a file socket');
        }

        return [
            'database.dsn' => sprintf('mysql:host=%s;port=%s;dbname=database', $hostAddress, $hostPort),
            'database.username' => 'username',
            'database.password' => 'password',
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
            'database.driver_options' => [PDO::ATTR_TIMEOUT => 2],
        ];
    }


    /**
     * A free port, found by opening a listening socket and closing it again.
     *
     * @throws \Exception
     */
    private static function findFreePort(): string
    {
        $socket = socket_create_listen(0);

        if (socket_getsockname($socket, $address, $port)) {
            socket_close($socket);

            return '' . $port;
        }

        throw new Exception('unable to allocate port');
    }
}
