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

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ScopeRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class ScopeRepositoryTest extends TestCase
{
    /**
     * @return void
     */
    public static function setUpBeforeClass()
    {
        $config = [
            'database.dsn' => 'sqlite::memory:',
            'database.username' => null,
            'database.password' => null,
            'database.prefix' => 'phpunit_',
            'database.persistent' => true,
            'database.slaves' => [],
        ];

        Configuration::loadFromArray($config, '', 'simplesaml');
        Configuration::setConfigDir(__DIR__ . '/../../config-template');
        (new DatabaseMigration())->migrate();
    }


    /**
     * @return void
     */
    public function testGetScopeEntityByIdentifier()
    {
        $scopeRepository = new ScopeRepository(new ConfigurationService());

        $scope = $scopeRepository->getScopeEntityByIdentifier('openid');

        $expected = ScopeEntity::fromData(
            'openid',
            'openid'
        );

        $this->assertEquals($expected, $scope);
    }


    /**
     * @return void
     */
    public function testGetUnknownScope()
    {
        $scopeRepository = new ScopeRepository(new ConfigurationService());

        $scope = $scopeRepository->getScopeEntityByIdentifier('none');

        $this->assertNull($scope);
    }


    /**
     * @return void
     */
    public function testFinalizeScopes()
    {
        $scopeRepository = new ScopeRepository(new ConfigurationService());
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
