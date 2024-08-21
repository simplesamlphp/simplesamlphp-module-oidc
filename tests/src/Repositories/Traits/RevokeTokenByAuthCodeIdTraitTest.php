<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Repositories\Traits;

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
     * @var ModuleConfig
     */
    protected ModuleConfig $moduleConfig;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;

    public static function setUpBeforeClass(): void
    {

        Configuration::setConfigDir(__DIR__ . '/../../../../config-templates');
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

    public static function loadPGDatabase(): array
    {
        $pgContainer = PostgresContainer::make('15.0', 'password');
        $pgContainer->withPostgresDatabase('database');
        $pgContainer->withPostgresUser('username');
        $hostPort = getenv('HOSTPORT') ?: '5432';
        $pgContainer->withPort($hostPort, '5432');

        $pgContainer->run();
        // Wait until the docker heartcheck is green
        $pgContainer->withWait(new WaitForHealthCheck());
        // Wait until that message is in the logs
        $pgContainer->withWait(new WaitForLog('Ready to accept connections'));

        $hostAddress = getenv('HOSTADDRESS') ?: $pgContainer->getAddress();
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

        $mysqlContainer->run();
        // Wait until the docker heartcheck is green
        $mysqlContainer->withWait(new WaitForHealthCheck());
        // Wait until that message is in the logs
        $mysqlContainer->withWait(new WaitForLog('Ready to accept connections'));

        $mysqlConfig = [
            'database.dsn' =>
                sprintf('mysql:host=%s;port=3306;dbname=database', $mysqlContainer->getAddress()),
            'database.username' => 'username',
            'database.password' => 'password',
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
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
        return ClientEntity::fromData(
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
}
