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
use JsonException;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use RuntimeException;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository
 */
class RefreshTokenRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'refresh_token_client_id';
    final public const USER_ID = 'refresh_token_user_id';
    final public const ACCESS_TOKEN_ID = 'refresh_token_access_token_id';
    final public const REFRESH_TOKEN_ID = 'refresh_token_id';

    protected static RefreshTokenRepository $repository;

    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     * @throws Error
     * @throws JsonException
     * @throws Exception
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

        $accessToken = AccessTokenEntity::fromData($client, [], self::USER_ID);
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(new DateTimeImmutable('yesterday'));
        (new AccessTokenRepository($moduleConfig))->persistNewAccessToken($accessToken);

        self::$repository = new RefreshTokenRepository($moduleConfig);
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_refresh_token', self::$repository->getTableName());
    }

    /**
     * @throws UniqueTokenIdentifierConstraintViolationException
     * @throws OidcServerException
     * @throws OAuthServerException
     * @throws Exception
     * @throws Exception
     */
    public function testAddAndFound(): void
    {
        $moduleConfig = new ModuleConfig();
        $accessToken = (new AccessTokenRepository($moduleConfig))->findById(self::ACCESS_TOKEN_ID);

        $refreshToken = self::$repository->getNewRefreshToken();
        $refreshToken->setIdentifier(self::REFRESH_TOKEN_ID);
        $refreshToken->setExpiryDateTime(DateTimeImmutable::createFromMutable(TimestampGenerator::utc('yesterday')));
        $refreshToken->setAccessToken($accessToken);

        self::$repository->persistNewRefreshToken($refreshToken);

        $foundRefreshToken = self::$repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertEquals($refreshToken, $foundRefreshToken);
    }

    /**
     * @throws OidcServerException
     */
    public function testAddAndNotFound(): void
    {
        $notFoundRefreshToken = self::$repository->findById('notoken');

        $this->assertNull($notFoundRefreshToken);
    }

    /**
     * @throws OidcServerException
     */
    public function testRevokeToken(): void
    {
        self::$repository->revokeRefreshToken(self::REFRESH_TOKEN_ID);
        $isRevoked = self::$repository->isRefreshTokenRevoked(self::REFRESH_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws OidcServerException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(RuntimeException::class);

        self::$repository->revokeRefreshToken('notoken');
    }

    /**
     * @throws OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(RuntimeException::class);

        self::$repository->isRefreshTokenRevoked('notoken');
    }

    /**
     * @throws OidcServerException
     * @throws Exception
     */
    public function testRemoveExpired(): void
    {
        self::$repository->removeExpired();
        $notFoundRefreshToken = self::$repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertNull($notFoundRefreshToken);
    }
}
