<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Test\Module\oidc\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\ScopeRepository
 */
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
        Configuration::setConfigDir(__DIR__ . '/../../../config-templates');
        (new DatabaseMigration())->migrate();
    }

    public function testGetScopeEntityByIdentifier(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig());

        $scope = $scopeRepository->getScopeEntityByIdentifier('openid');

        $expected = ScopeEntity::fromData(
            'openid',
            'openid'
        );

        $this->assertEquals($expected, $scope);
    }

    public function testGetUnknownScope(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig());

        $this->assertNull($scopeRepository->getScopeEntityByIdentifier('none'));
    }

    public function testFinalizeScopes(): void
    {
        $scopeRepository = new ScopeRepository(new ModuleConfig());
        $scopes = [
            ScopeEntity::fromData('openid'),
            ScopeEntity::fromData('basic'),
        ];
        $client = ClientRepositoryTest::getClient('clientid');

        $finalizedScopes = $scopeRepository->finalizeScopes($scopes, 'any', $client);

        $expectedScopes = [
            ScopeEntity::fromData('openid'),
        ];
        $this->assertEquals($expectedScopes, $finalizedScopes);
    }
}
