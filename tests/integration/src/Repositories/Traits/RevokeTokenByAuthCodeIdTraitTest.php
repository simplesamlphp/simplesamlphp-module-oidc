<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Repositories\Traits;

use DateTimeImmutable;
use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AbstractDatabaseRepository;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use Testcontainers\Container\MySQLContainer;
use Testcontainers\Container\PostgresContainer;
use Testcontainers\Wait\WaitForHealthCheck;
use Testcontainers\Wait\WaitForLog;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait
 */
class RevokeTokenByAuthCodeIdTraitTest extends TestCase
{
    protected array $state;
    protected array $scopes;
    protected string $expiresAt;

    final public const IS_REVOKED = false;
    final public const AUTH_CODE_ID = 'authCode123';
    final public const REQUESTED_CLAIMS = ['key' => 'value'];
    final public const CLIENT_ID = 'access_token_client_id';
    final public const USER_ID = 'access_token_user_id';
    final public const ACCESS_TOKEN_ID = 'access_token_id';

    protected AccessTokenRepository $repository;

    public static array $pgConfig;
    public static array $mysqlConfig;
    public static array $sqliteConfig;

    /**
     * @var AbstractDatabaseRepository
     */
    protected $mock;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;

    private static ?string $containerAddress = null;
    private static ?string $mysqlPort = null;
    private static ?string $postgresPort = null;

    public static function setUpBeforeClass(): void
    {
        self::$containerAddress = getenv('HOSTADDRESS') ?: null;
        self::$mysqlPort = getenv('HOSTPORT_MY') ?: null;
        self::$postgresPort = getenv('HOSTPORT_PG') ?: null;
        // Mac docker seems to require connecting to localhost and mapped port to access containers
        if (PHP_OS_FAMILY === 'Darwin' && getenv('HOSTADDRESS') === false) {
            //phpcs:ignore Generic.Files.LineLength.TooLong
            echo "Defaulting docker host address to 127.0.0.1. Disable this behavior by setting HOSTADDRESS to a blank.\n\tHOSTADDRESS= ./vendor/bin/phpunit";
            self::$containerAddress = "127.0.0.1";
        } else {
            //Use the container ips and ports if not on a Mac
            self::$mysqlPort ??= "3306";
            self::$postgresPort ??= "5432";
        }
        Configuration::setConfigDir(__DIR__ . '/../../../../../config-templates');
        self::$pgConfig = self::loadPGDatabase();
        self::$mysqlConfig = self::loadMySqlDatabase();
        self::$sqliteConfig = self::loadSqliteDatabase();
    }

    public function useDatabase($config): void
    {
        $configuration = Configuration::loadFromArray($config, '', 'simplesaml');

        $database = Database::getInstance($configuration);
        (new DatabaseMigration($database))->migrate();

        $moduleConfig = new ModuleConfig();

        $this->mock = new class ($moduleConfig) extends AbstractDatabaseRepository {
            use RevokeTokenByAuthCodeIdTrait;

            public function getTableName(): ?string
            {
                return $this->database->applyPrefix('oidc_access_token');
            }

            public function generateQueryWrapper(string $authCodeId, array $revokedParam): array
            {
                return $this->generateQuery($authCodeId, $revokedParam);
            }

            public function getDatabase(): Database
            {
                return $this->database;
            }
        };

        $this->repository = new AccessTokenRepository($moduleConfig);


        $client = self::clientRepositoryGetClient(self::CLIENT_ID);
        $clientRepositoryMock = new ClientRepository($moduleConfig);
        $this->mock->getDatabase()->write('DELETE from ' . $clientRepositoryMock->getTableName());
        $clientRepositoryMock->add($client);


        $user = UserEntity::fromData(self::USER_ID);
        $userRepositoryMock = new UserRepository($moduleConfig);
        $this->mock->getDatabase()->write('DELETE from ' . $userRepositoryMock->getTableName());
        $userRepositoryMock->add($user);
    }

    /**
     * @throws \Exception
     */
    public static function loadPGDatabase(): array
    {
        $pgContainer = PostgresContainer::make('15.0', 'password');
        $pgContainer->withPostgresDatabase('database');
        $pgContainer->withPostgresUser('username');
        $hostPort = self::$postgresPort ?: self::findFreePort();
        $pgContainer->withPort($hostPort, '5432');

        $pgContainer->run();
        // Wait until the docker heartcheck is green
        $pgContainer->withWait(new WaitForHealthCheck());
        // Wait until that message is in the logs
        $pgContainer->withWait(new WaitForLog('Ready to accept connections'));

        $hostAddress = self::$containerAddress ?: $pgContainer->getAddress();
        $pgConfig = [
            'database.dsn' => sprintf(
                'pgsql:host=%s;port=%s;dbname=database',
                $hostAddress,
                $hostPort,
            ),
            'database.username' => 'username',
            'database.password' => 'password',
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
            'database.driver_options' => [
                PDO::ATTR_TIMEOUT => 2, // Timeout quickly if there are docker issues
            ],
        ];

        return $pgConfig;
    }

    public static function loadSqliteDatabase(): array
    {
        $config = [
            'database.dsn'         => 'sqlite::memory:',
            'database.username'    => null,
            'database.password'    => null,
            'database.prefix'      => 'phpunit_',
            'database.persistent'  => true,
            'database.secondaries' => [],
        ];

        return $config;
    }

    public static function loadMySqlDatabase(): array
    {
        $mysqlContainer = MySQLContainer::make('8.0');
        $mysqlContainer->withMySQLDatabase('database');
        $mysqlContainer->withMySQLUser('username', 'password');
        $hostPort = self::$mysqlPort ?: self::findFreePort();
        $mysqlContainer->withPort($hostPort, '3306');

        $mysqlContainer->run();
        // Wait until the docker heartcheck is green
        $mysqlContainer->withWait(new WaitForHealthCheck());
        // Wait until that message is in the logs
        $mysqlContainer->withWait(new WaitForLog('Ready to accept connections'));

        $hostAddress = self::$containerAddress ?: $mysqlContainer->getAddress();
        if ($hostAddress === 'localhost') {
            //phpcs:ignore Generic.Files.LineLength.TooLong
            throw new \Exception('To connect to localhost with mysql use IP 127.0.0.1, otherwise mysql tries to use a file socket');
        }
        $mysqlConfig = [
            'database.dsn' =>
                sprintf('mysql:host=%s;port=%s;dbname=database', $hostAddress, $hostPort),
            'database.username' => 'username',
            'database.password' => 'password',
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
            'database.driver_options' => [
                PDO::ATTR_TIMEOUT => 2, // Timeout quickly if there are docker issues
            ],
        ];


        return $mysqlConfig;
    }

    /**
     * @return void
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        $this->scopeEntityOpenId = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenId->method('jsonSerialize')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntity::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntityProfile->method('jsonSerialize')->willReturn('profile');
        $this->scopes = [$this->scopeEntityOpenId, $this->scopeEntityProfile,];
    }

    public static function databaseToTest(): array
    {
        return [
            'PostgreSql' => ['pgConfig'],
            'MySql' => ['mysqlConfig'],
            'Sqlite' => ['sqliteConfig'],
        ];
    }

    /**
     * @return void
     */
    #[DataProvider('databaseToTest')]
    public function testItGenerateQuery(string $database): void
    {
        $this->useDatabase(self::$$database);

        $revokedParam = [self::IS_REVOKED, PDO::PARAM_BOOL];
        $expected = [
            'UPDATE phpunit_oidc_access_token SET is_revoked = :is_revoked WHERE auth_code_id = :auth_code_id',
            [
                'auth_code_id' => self::AUTH_CODE_ID,
                'is_revoked' => $revokedParam,
            ],
        ];

        $this->assertEquals(
            $expected,
            $this->mock->generateQueryWrapper(self::AUTH_CODE_ID, $revokedParam),
        );
    }

    /**
     * @return void
     * @throws \JsonException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Error\Error
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */

    #[DataProvider('databaseToTest')]
    public function testRevokeByAuthCodeId(string $database): void
    {
        $this->useDatabase(self::$$database);

        $accessToken = $this->repository->getNewToken(
            self::clientRepositoryGetClient(self::CLIENT_ID),
            $this->scopes,
            self::USER_ID,
            self::AUTH_CODE_ID,
            self::REQUESTED_CLAIMS,
        );
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc('yesterday'),
        ));

        $this->repository->persistNewAccessToken($accessToken);

        $isRevoked = $this->repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);
        $this->assertFalse($isRevoked);

        // Revoke the access token
        $this->mock->revokeByAuthCodeId(self::AUTH_CODE_ID);
        $isRevoked = $this->repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @param   string       $id
     * @param   bool         $enabled
     * @param   bool         $confidential
     * @param   string|null  $owner
     *
     * @return ClientEntityInterface
     */
    public static function clientRepositoryGetClient(
        string $id,
        bool $enabled = true,
        bool $confidential = false,
        ?string $owner = null,
    ): ClientEntityInterface {
        return new ClientEntity(
            $id,
            'clientsecret',
            'Client',
            'Description',
            ['http://localhost/redirect'],
            ['openid'],
            $enabled,
            $confidential,
            'admin',
            $owner,
        );
    }

    /**
     * Determine a free port for the docker container
     * by creating a closing a socket
     */
    private static function findFreePort(): string
    {
        $sock = socket_create_listen(0);
        if (socket_getsockname($sock, $addr, $port)) {
            socket_close($sock);
            return '' . $port;
        } else {
            throw new \Exception('unable to allocate port');
        }
    }
}
