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
use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use SimpleSAML\Module\oidc\Entity\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AccessTokenRepository
 */
class AccessTokenRepositoryTest extends TestCase
{
    public const CLIENT_ID = 'access_token_client_id';
    public const USER_ID = 'access_token_user_id';
    public const ACCESS_TOKEN_ID = 'access_token_id';

    /**
     * @var AccessTokenRepository
     */
    protected static $repository;

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
        (new DatabaseMigration())->migrate();

        $configurationService = new ConfigurationService();

        $client = ClientRepositoryTest::getClient(self::CLIENT_ID);
        (new ClientRepository($configurationService))->add($client);
        $user = UserEntity::fromData(self::USER_ID);
        (new UserRepository($configurationService))->add($user);

        self::$repository = new AccessTokenRepository($configurationService);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_access_token', self::$repository->getTableName());
    }

    public function testAddAndFound(): void
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $accessToken = self::$repository->getNewToken(
            ClientRepositoryTest::getClient(self::CLIENT_ID),
            $scopes,
            self::USER_ID
        );
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(\DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc('yesterday')
        ));

        self::$repository->persistNewAccessToken($accessToken);

        $foundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($accessToken, $foundAccessToken);
    }

    public function testAddAndNotFound(): void
    {
        $notFoundAccessToken = self::$repository->findById('notoken');

        $this->assertNull($notFoundAccessToken);
    }

    public function testRevokeToken(): void
    {
        self::$repository->revokeAccessToken(self::ACCESS_TOKEN_ID);
        $isRevoked = self::$repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(\RuntimeException::class);

        self::$repository->revokeAccessToken('notoken');
    }

    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(\RuntimeException::class);

        self::$repository->isAccessTokenRevoked('notoken');
    }

    public function testRemoveExpired(): void
    {
        self::$repository->removeExpired();
        $notFoundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }
}
