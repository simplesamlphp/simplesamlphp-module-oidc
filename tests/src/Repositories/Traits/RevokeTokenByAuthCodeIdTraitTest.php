<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Repositories\Traits;

use PDO;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AbstractDatabaseRepository;
use SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\Traits\RevokeTokenByAuthCodeIdTrait
 */
class RevokeTokenByAuthCodeIdTraitTest extends TestCase
{
    protected array $state;
    protected string $id = '123';
    protected array $scopes;
    protected string $expiresAt;
    protected string $userId = 'user123';
    protected bool $isRevoked = false;
    protected string $authCodeId = 'authCode123';
    protected array $requestedClaims = ['key' => 'value'];
    protected string $clientId = 'client123';

    /**
     * @var AbstractDatabaseRepository|__anonymous@856
     */
    protected $mock;

    /**
     * @var MockObject|(object&MockObject)|ModuleConfig|(ModuleConfig&object&MockObject)|(ModuleConfig&MockObject)
     */
    protected MockObject $moduleConfigMock;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityOpenId;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ScopeEntity
     */
    protected ScopeEntity $scopeEntityProfile;

    /**
     * @var \SimpleSAML\Module\oidc\Entities\ClientEntity
     */
    protected ClientEntity $clientEntityStub;

    /**
     * @var Configuration
     */
    protected $config;

    /**
     * @var Database
     */
    protected Database $db;


    /**
     * @return void
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        Configuration::clearInternalState();
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->mock = new class ($this->moduleConfigMock) extends AbstractDatabaseRepository {
            use RevokeTokenByAuthCodeIdTrait;

            public function getTableName(): ?string
            {
                return $this->database->applyPrefix('oidc_access_token');
            }

            public function generateQueryWrapper(string $authCodeId, array $revokedParam): array
            {
                return $this->generateQuery($authCodeId, $revokedParam);
            }

            public function setDatabaseInstance(Database $db): void
            {
                $this->database = $db;
            }

            public function getDatabase(): Database
            {
                return $this->database;
            }
        };

        $config = [
            'database.dsn'        => 'sqlite::memory:',
            'database.username'   => null,
            'database.password'   => null,
            'database.prefix'     => 'phpunit_',
            'database.persistent' => true,
            'database.secondaries'     => [],
        ];

        $this->config = new Configuration($config, "test/SimpleSAML/DatabaseTest.php");

        // Ensure that we have a functional configuration class
        $this->assertEquals($config['database.dsn'], $this->config->getString('database.dsn'));

        $this->db = Database::getInstance($this->config);
        $table = $this->db->applyPrefix("oidc_access_token");
        $createQuery = sprintf(
            'CREATE TABLE IF NOT EXISTS %s (
                id VARCHAR(191) PRIMARY KEY NOT NULL,
                scopes TEXT,
                expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_id VARCHAR(191) NOT NULL,
                client_id VARCHAR(191) NOT NULL,
                is_revoked BOOLEAN NOT NULL DEFAULT false,
                auth_code_id varchar(191) DEFAULT NULL,
                requested_claims TEXT NULL
                )',
            $table,
        );
        $this->db->write($createQuery);

        $this->clientEntityStub = $this->createStub(ClientEntity::class);
        $this->clientEntityStub->method('getIdentifier')->willReturn($this->clientId);
        $this->scopeEntityOpenId = $this->createStub(ScopeEntity::class);
        $this->scopeEntityOpenId->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOpenId->method('jsonSerialize')->willReturn('openid');
        $this->scopeEntityProfile = $this->createStub(ScopeEntity::class);
        $this->scopeEntityProfile->method('getIdentifier')->willReturn('profile');
        $this->scopeEntityProfile->method('jsonSerialize')->willReturn('profile');
        $this->scopes = [$this->scopeEntityOpenId, $this->scopeEntityProfile,];

        $this->expiresAt = date('Y-m-d H:i:s', strtotime('+10 minutes'));

        $this->state = [
            'id' => $this->id,
            'scopes' => json_encode($this->scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $this->expiresAt,
            'user_id' => $this->userId,
            'client_id' => $this->clientEntityStub->getIdentifier(),
            'is_revoked' => $this->isRevoked,
            'auth_code_id' => $this->authCodeId,
            'requested_claims' => json_encode($this->requestedClaims, JSON_THROW_ON_ERROR),
        ];
    }

    /**
     * @return void
     */
    public function testItGenerateQuery(): void
    {
        $revokedParam = [true, PDO::PARAM_BOOL];
        $expected = [
            'UPDATE oidc_access_token SET is_revoked = :is_revoked WHERE auth_code_id = :auth_code_id',
            [
                'auth_code_id' => $this->authCodeId,
                'is_revoked' => $revokedParam,
            ],
        ];

        $this->assertEquals(
            $expected,
            $this->mock->generateQueryWrapper($this->authCodeId, $revokedParam),
        );
    }

    public function testRevokeByAuthCodeId(): void
    {
        $table = $this->db->applyPrefix("oidc_access_token");
        $this->mock->setDatabaseInstance($this->db);

        $stmt = sprintf(
            'INSERT INTO %s (id, scopes, expires_at, user_id, client_id, is_revoked, auth_code_id, requested_claims) '
            . 'VALUES (:id, :scopes, :expires_at, :user_id, :client_id, :is_revoked, :auth_code_id, :requested_claims)',
            $this->mock->getTableName(),
        );

        // Truncate the table(assume SQLITE)
        $this->mock->getDatabase()->write("DELETE from $table");
        // Add valid access token
        $this->mock->getDatabase()->write(
            $stmt,
            $this->state,
        );
        // Run revoke
        $this->mock->revokeByAuthCodeId($this->authCodeId);

        $queryResponse = $this->mock->getDatabase()->read("SELECT is_revoked FROM {$table} where id={$this->id}");
        $isRevoked = $queryResponse->fetch()[0];
        $this->assertIsBool(filter_var($isRevoked, FILTER_VALIDATE_BOOL));
        $this->assertTrue(filter_var($isRevoked, FILTER_VALIDATE_BOOL));
    }
}
