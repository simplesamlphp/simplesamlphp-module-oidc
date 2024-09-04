<?php

declare(strict_types=1);

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

use DateTimeImmutable;
use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AccessTokenRepository
 */
class AccessTokenRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'access_token_client_id';
    final public const USER_ID = 'access_token_user_id';
    final public const ACCESS_TOKEN_ID = 'access_token_id';

    protected static AccessTokenRepository $repository;

    /**
     * @throws \Exception
     */
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

        $moduleConfig = new ModuleConfig();

        $client = ClientRepositoryTest::getClient(self::CLIENT_ID);
        (new ClientRepository($moduleConfig))->add($client);
        $user = UserEntity::fromData(self::USER_ID);
        (new UserRepository($moduleConfig))->add($user);

        self::$repository = new AccessTokenRepository($moduleConfig);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_access_token', self::$repository->getTableName());
    }

    /**
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Error\Error
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     * @throws \Exception
     */
    public function testAddAndFound(): void
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $accessToken = self::$repository->getNewToken(
            ClientRepositoryTest::getClient(self::CLIENT_ID),
            $scopes,
            self::USER_ID,
        );
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc('yesterday'),
        ));

        self::$repository->persistNewAccessToken($accessToken);

        $foundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($accessToken, $foundAccessToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddAndNotFound(): void
    {
        $notFoundAccessToken = self::$repository->findById('notoken');

        $this->assertNull($notFoundAccessToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testRevokeToken(): void
    {
        self::$repository->revokeAccessToken(self::ACCESS_TOKEN_ID);
        $isRevoked = self::$repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(Exception::class);

        self::$repository->revokeAccessToken('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(Exception::class);

        self::$repository->isAccessTokenRevoked('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testRemoveExpired(): void
    {
        self::$repository->removeExpired();
        $notFoundAccessToken = self::$repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }
}
