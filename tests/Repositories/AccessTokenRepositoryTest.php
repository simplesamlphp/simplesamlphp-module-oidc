<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Repositories;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;
use SimpleSAML\Modules\OpenIDConnect\Entity\UserEntity;
use SimpleSAML\Modules\OpenIDConnect\Repositories\AccessTokenRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\ClientRepository;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration;

class AccessTokenRepositoryTest extends TestCase
{
    const CLIENT_ID = 'access_token_client_id';
    const USER_ID = 'access_token_user_id';
    const ACCESS_TOKEN_ID = 'access_token_id';

    /**
     * @var AccessTokenRepository
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

        self::$repository = new AccessTokenRepository();
    }

    public function testGetTableName()
    {
        $this->assertSame('phpunit_oidc_access_token', self::$repository->getTableName());
    }

    public function testAddAndFound()
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $accessToken = self::$repository->getNewToken(ClientRepositoryTest::getClient(self::CLIENT_ID), $scopes, self::USER_ID);
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(new \DateTime('yesterday'));

        self::$repository->persistNewAccessToken($accessToken);

        $foundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($accessToken, $foundAccessToken);
    }

    public function testAddAndNotFound()
    {
        $notFoundAccessToken = self::$repository->findById('notoken');

        $this->assertNull($notFoundAccessToken);
    }

    public function testRevokeToken()
    {
        self::$repository->revokeAccessToken(self::ACCESS_TOKEN_ID);
        $isRevoked = self::$repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testErrorRevokeInvalidToken()
    {
        self::$repository->revokeAccessToken('notoken');
    }

    /**
     * @expectedException \RuntimeException
     */
    public function testErrorCheckIsRevokedInvalidToken()
    {
        self::$repository->isAccessTokenRevoked('notoken');
    }

    public function testRemoveExpired()
    {
        self::$repository->removeExpired();
        $notFoundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }
}
