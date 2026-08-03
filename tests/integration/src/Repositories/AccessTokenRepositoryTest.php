<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Repositories;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ScopeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AbstractDatabaseRepository;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\Test\Module\oidc\integration\DatabaseContainers;

#[CoversClass(AccessTokenRepository::class)]
class AccessTokenRepositoryTest extends TestCase
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

    protected AccessTokenRepository $accessTokenRepository;

    public static array $pgConfig;
    public static array $mysqlConfig;
    public static array $sqliteConfig;

    protected AbstractDatabaseRepository $mock;
    protected ScopeEntity $scopeEntityOpenId;
    protected ScopeEntity $scopeEntityProfile;

    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $accessTokenEntityMock;
    protected array $accessTokenState;
    protected AccessTokenEntityFactory $accessTokenEntityFactory;
    protected MockObject $jwsMock;
    protected MockObject $moduleConfigMock;

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

        $this->accessTokenState = [
            'id' => self::ACCESS_TOKEN_ID,
            'scopes' => '{"openid":"openid","profile":"profile"}',
            'expires_at' => date('Y-m-d H:i:s', time() - 60), // expired...
            'user_id' => self::USER_ID,
            'client_id' => self::CLIENT_ID,
            'is_revoked' => false,
            'auth_code_id' => self::AUTH_CODE_ID,
            'requested_claims' => '[]',
            'flow_type' => null,
            'authorization_details' => null,
            'bound_client_id' => null,
            'bound_redirect_uri' => null,
            'issuer_state' => null,
        ];

        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);

        $this->jwsMock = $this->createMock(Jws::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->accessTokenEntityFactory = new AccessTokenEntityFactory(
            new Helpers(),
            new ScopeEntityFactory(),
            $this->jwsMock,
            $this->moduleConfigMock,
        );
    }

    public function useDatabase($config): void
    {
        $configuration = Configuration::loadFromArray($config, '', 'simplesaml');

        $database = Database::getInstance($configuration);
        (new DatabaseMigration($database))->migrate();

        $moduleConfig = new ModuleConfig();

        $this->mock = new class ($moduleConfig, $database, null) extends AbstractDatabaseRepository {
            public function getTableName(): ?string
            {
                return $this->database->applyPrefix('oidc_access_token');
            }

            public function getDatabase(): Database
            {
                return $this->database;
            }
        };

        $clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $clientEntityMock->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $clientEntityFactoryMock->method('fromState')->willReturn($clientEntityMock);

        $database = Database::getInstance();

        $clientRepositoryMock = new ClientRepository(
            $moduleConfig,
            $database,
            null,
            $clientEntityFactoryMock,
        );

        $this->accessTokenRepository = new AccessTokenRepository(
            $moduleConfig,
            $database,
            null,
            $clientRepositoryMock,
            $this->accessTokenEntityFactory,
            new Helpers(),
        );

        $client = self::clientRepositoryGetClient(self::CLIENT_ID);
        $this->mock->getDatabase()->write('DELETE from ' . $clientRepositoryMock->getTableName());
        $clientRepositoryMock->add($client);

        $createUpdatedAt = new \DateTimeImmutable();
        $helpers = new Helpers();
        $user = new UserEntity(self::USER_ID, $createUpdatedAt, $createUpdatedAt, []);
        $userRepositoryMock = new UserRepository(
            $moduleConfig,
            $database,
            null,
            $helpers,
            new UserEntityFactory($helpers),
        );
        $this->mock->getDatabase()->write('DELETE from ' . $userRepositoryMock->getTableName());
        $userRepositoryMock->add($user);
    }

    public static function databaseToTest(): array
    {
        return DatabaseContainers::all();
    }

    /**
     * @throws \JsonException
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Error\Error
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */

    #[DataProvider('databaseToTest')]
    public function testRevokeByAuthCodeId(string $database): void
    {
        $this->useDatabase(self::$$database);

        $this->accessTokenEntityMock->method('getState')->willReturn($this->accessTokenState);

        $this->accessTokenRepository->persistNewAccessToken($this->accessTokenEntityMock);

        $isRevoked = $this->accessTokenRepository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);
        $this->assertFalse($isRevoked);

        // Revoke the access token
        $this->accessTokenRepository->revokeByAuthCodeId(self::AUTH_CODE_ID);
        $isRevoked = $this->accessTokenRepository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

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
}
