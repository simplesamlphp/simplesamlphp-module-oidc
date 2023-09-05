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
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AuthCodeRepository
 */
class AuthCodeRepositoryTest extends TestCase
{
    public const CLIENT_ID = 'auth_code_client_id';
    public const USER_ID = 'auth_code_user_id';
    public const AUTH_CODE_ID = 'auth_code_id';
    public const REDIRECT_URI = 'http://localhost/redirect';

    /**
     * @var AuthCodeRepository
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

        self::$repository = new AuthCodeRepository($configurationService);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_auth_code', self::$repository->getTableName());
    }

    public function testAddAndFound(): void
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $authCode = self::$repository->getNewAuthCode();

        $authCode->setIdentifier(self::AUTH_CODE_ID);
        $authCode->setClient(ClientRepositoryTest::getClient(self::CLIENT_ID));
        $authCode->setUserIdentifier(self::USER_ID);
        $authCode->setExpiryDateTime(\DateTimeImmutable::createFromMutable(TimestampGenerator::utc('yesterday')));
        $authCode->setRedirectUri(self::REDIRECT_URI);
        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        self::$repository->persistNewAuthCode($authCode);

        $foundAuthCode = self::$repository->findById(self::AUTH_CODE_ID);

        $this->assertEquals($authCode, $foundAuthCode);
    }

    public function testAddAndNotFound(): void
    {
        $notFoundAuthCode = self::$repository->findById('nocode');

        $this->assertNull($notFoundAuthCode);
    }

    public function testRevokeCode(): void
    {
        self::$repository->revokeAuthCode(self::AUTH_CODE_ID);
        $isRevoked = self::$repository->isAuthCodeRevoked(self::AUTH_CODE_ID);

        $this->assertTrue($isRevoked);
    }

    public function testErrorRevokeInvalidAuthCode(): void
    {
        $this->expectException(\Exception::class);

        self::$repository->revokeAuthCode('nocode');
    }

    public function testErrorCheckIsRevokedInvalidAuthCode(): void
    {
        $this->expectException(\Exception::class);

        self::$repository->isAuthCodeRevoked('nocode');
    }

    public function testRemoveExpired(): void
    {
        self::$repository->removeExpired();
        $notFoundAuthCode = self::$repository->findById(self::AUTH_CODE_ID);

        $this->assertNull($notFoundAuthCode);
    }
}
