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
use SimpleSAML\Modules\OpenIDConnect\Entity\AccessTokenEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\RefreshTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class RefreshTokenRepositoryTest extends TestCase
{
    const CLIENT_ID = 'refresh_token_client_id';
    const USER_ID = 'refresh_token_user_id';
    const ACCESS_TOKEN_ID = 'refresh_token_access_token_id';
    const REFRESH_TOKEN_ID = 'refresh_token_id';

    /**
     * @var RefreshTokenRepository
     */
    protected static $repository;

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

        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();

        $client = ClientRepositoryTest::getClient(self::CLIENT_ID);
        (new ClientRepository())->add($client);
        $user = UserEntity::fromData(self::USER_ID);
        (new UserRepository())->add($user);

        $accessToken = AccessTokenEntity::fromData($client, [], self::USER_ID);
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(new \DateTime('yesterday'));
        (new AccessTokenRepository())->persistNewAccessToken($accessToken);

        self::$repository = new RefreshTokenRepository();
    }

    public function testGetTableName()
    {
        $this->assertSame('phpunit_oidc_refresh_token', self::$repository->getTableName());
    }

    public function testAddAndFound()
    {
        $accessToken = (new AccessTokenRepository())->findById(self::ACCESS_TOKEN_ID);

        $refreshToken = self::$repository->getNewRefreshToken();
        $refreshToken->setIdentifier(self::REFRESH_TOKEN_ID);
        $refreshToken->setExpiryDateTime(new \DateTime('yesterday'));
        $refreshToken->setAccessToken($accessToken);

        self::$repository->persistNewRefreshToken($refreshToken);

        $foundRefreshToken = self::$repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertEquals($refreshToken, $foundRefreshToken);
    }

    public function testAddAndNotFound()
    {
        $notFoundRefreshToken = self::$repository->findById('notoken');

        $this->assertNull($notFoundRefreshToken);
    }

    public function testRevokeToken()
    {
        self::$repository->revokeRefreshToken(self::REFRESH_TOKEN_ID);
        $isRevoked = self::$repository->isRefreshTokenRevoked(self::REFRESH_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testErrorRevokeInvalidToken()
    {
        self::$repository->revokeRefreshToken('notoken');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testErrorCheckIsRevokedInvalidToken()
    {
        self::$repository->isRefreshTokenRevoked('notoken');
    }

    public function testRemoveExpired()
    {
        self::$repository->removeExpired();
        $notFoundRefreshToken = self::$repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertNull($notFoundRefreshToken);
    }
}
