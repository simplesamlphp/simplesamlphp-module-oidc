<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Repositories\Traits;

use DateTimeImmutable;
use PDO;
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

    protected static AccessTokenRepository $repository;

    /**
     * @var AbstractDatabaseRepository
     */
    protected static $mock;

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
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries' => [],
        ];

        Configuration::loadFromArray($config, '', 'simplesaml');
        Configuration::setConfigDir(__DIR__ . '/../../../../config-templates');
        (new DatabaseMigration())->migrate();

        $moduleConfig = new ModuleConfig();

        self::$mock = new class ($moduleConfig) extends AbstractDatabaseRepository {
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

        self::$repository = new AccessTokenRepository($moduleConfig);


        $client = self::clientRepositoryGetClient(self::CLIENT_ID);
        $clientRepositoryMock = new ClientRepository($moduleConfig);
        self::$mock->getDatabase()->write('DELETE from ' . $clientRepositoryMock->getTableName());
        $clientRepositoryMock->add($client);


        $user = UserEntity::fromData(self::USER_ID);
        $userRepositoryMock = new UserRepository($moduleConfig);
        self::$mock->getDatabase()->write('DELETE from ' . $userRepositoryMock->getTableName());
        $userRepositoryMock->add($user);
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

    /**
     * @return void
     */
    public function testItGenerateQuery(): void
    {
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
            self::$mock->generateQueryWrapper(self::AUTH_CODE_ID, $revokedParam),
        );
    }

    public function testRevokeByAuthCodeId(): void
    {
        $accessToken = self::$repository->getNewToken(
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

        self::$repository->persistNewAccessToken($accessToken);

        self::$mock->revokeByAuthCodeId(self::AUTH_CODE_ID);
        $isRevoked = self::$repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

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
