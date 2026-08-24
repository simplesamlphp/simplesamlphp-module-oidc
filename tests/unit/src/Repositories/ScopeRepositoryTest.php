<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ScopeEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\ScopeRepository
 */
#[AllowMockObjectsWithoutExpectations]
class ScopeRepositoryTest extends TestCase
{
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
        Configuration::setConfigDir(__DIR__ . '/../../../config');
        (new DatabaseMigration())->migrate();
    }


    /**
     * @throws \Exception
     */
    public function testGetScopeEntityByIdentifier(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig(), new ScopeEntityFactory());

        $scope = $scopeRepository->getScopeEntityByIdentifier('openid');

        $expected = new ScopeEntity(
            'openid',
            'openid',
        );

        $this->assertEquals($expected, $scope);
    }


    /**
     * @throws \Exception
     */
    public function testGetUnknownScope(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig(), new ScopeEntityFactory());

        $this->assertNull($scopeRepository->getScopeEntityByIdentifier('none'));
    }


    /**
     * @throws \Exception
     */
    public function testFinalizeScopes(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig(), new ScopeEntityFactory());
        $scopes = [
            new ScopeEntity('openid'),
            new ScopeEntity('basic'),
        ];
        $client = ClientRepositoryTest::getClient('clientid');

        $finalizedScopes = $scopeRepository->finalizeScopes($scopes, 'any', $client);

        $expectedScopes = [
            new ScopeEntity('openid'),
        ];
        $this->assertEquals($expectedScopes, $finalizedScopes);
    }


    public function testFinalizeScopesReturnsEmptyIfNotClientEntity(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig(), new ScopeEntityFactory());
        $scopes = [
            new ScopeEntity('openid'),
            new ScopeEntity('basic'),
        ];

        $clientMock = $this->createMock(ClientEntityInterface::class);

        $this->assertEmpty($scopeRepository->finalizeScopes($scopes, 'any', $clientMock));
    }
}
