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
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AuthCodeRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AuthCodeRepositoryTest extends TestCase
{
    const CLIENT_ID = 'auth_code_client_id';
    const USER_ID = 'auth_code_user_id';
    const AUTH_CODE_ID = 'auth_code_id';
    const REDIRECT_URI = 'http://localhost/redirect';

    /**
     * @var AuthCodeRepository
     */
    protected static $repository;


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
        (new DatabaseMigration())->migrate();

        $client = ClientRepositoryTest::getClient(self::CLIENT_ID);
        (new ClientRepository())->add($client);
        $user = UserEntity::fromData(self::USER_ID);
        (new UserRepository())->add($user);

        self::$repository = new AuthCodeRepository();
    }


    /**
     * @return void
     */
    public function testGetTableName()
    {
        $this->assertSame('phpunit_oidc_auth_code', self::$repository->getTableName());
    }


    /**
     * @return void
     */
    public function testAddAndFound()
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $authCode = self::$repository->getNewAuthCode();

        $authCode->setIdentifier(self::AUTH_CODE_ID);
        $authCode->setClient(ClientRepositoryTest::getClient(self::CLIENT_ID));
        $authCode->setUserIdentifier(self::USER_ID);
        $authCode->setExpiryDateTime(TimestampGenerator::utc('yesterday'));
        $authCode->setRedirectUri(self::REDIRECT_URI);
        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        self::$repository->persistNewAuthCode($authCode);

        $foundAuthCode = self::$repository->findById(self::AUTH_CODE_ID);

        $this->assertEquals($authCode, $foundAuthCode);
    }


    /**
     * @return void
     */
    public function testAddAndNotFound()
    {
        $notFoundAuthCode = self::$repository->findById('nocode');

        $this->assertNull($notFoundAuthCode);
    }


    /**
     * @return void
     */
    public function testRevokeCode()
    {
        self::$repository->revokeAuthCode(self::AUTH_CODE_ID);
        $isRevoked = self::$repository->isAuthCodeRevoked(self::AUTH_CODE_ID);

        $this->assertTrue($isRevoked);
    }


    /**
     * @expectedException \RuntimeException
     * @return void
     */
    public function testErrorRevokeInvalidAuthCode()
    {
        self::$repository->revokeAuthCode('nocode');
    }


    /**
     * @expectedException \RuntimeException
     * @return void
     */
    public function testErrorCheckIsRevokedInvalidAuthCode()
    {
        self::$repository->isAuthCodeRevoked('nocode');
    }


    /**
     * @return void
     */
    public function testRemoveExpired()
    {
        self::$repository->removeExpired();
        $notFoundAuthCode = self::$repository->findById(self::AUTH_CODE_ID);

        $this->assertNull($notFoundAuthCode);
    }
}
