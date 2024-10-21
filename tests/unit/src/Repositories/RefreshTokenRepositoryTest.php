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
namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository
 */
class RefreshTokenRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'refresh_token_client_id';
    final public const USER_ID = 'refresh_token_user_id';
    final public const ACCESS_TOKEN_ID = 'refresh_token_access_token_id';
    final public const REFRESH_TOKEN_ID = 'refresh_token_id';

    protected RefreshTokenRepository $repository;
    protected MockObject $accessTokenMock;
    protected MockObject $accessTokenRepositoryMock;
    protected MockObject $refreshTokenEntityFactoryMock;
    protected MockObject $refreshTokenEntityMock;

    /**
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Error\Error
     * @throws \JsonException
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
    }

    protected function setUp(): void
    {
        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getIdentifier')->willReturn(self::ACCESS_TOKEN_ID);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->refreshTokenEntityFactoryMock = $this->createMock(RefreshTokenEntityFactory::class);

        $this->refreshTokenEntityMock = $this->createMock(RefreshTokenEntity::class);

        $this->repository = new RefreshTokenRepository(
            new ModuleConfig(),
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_refresh_token', $this->repository->getTableName());
    }

    /**
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Exception
     */
    public function testAddAndFound(): void
    {
        $refreshToken = new RefreshTokenEntity(
            self::REFRESH_TOKEN_ID,
            new DateTimeImmutable('yesterday', new DateTimeZone('UTC')),
            $this->accessTokenMock,
        );
        $this->repository->persistNewRefreshToken($refreshToken);

        $this->refreshTokenEntityFactoryMock->expects($this->once())
            ->method('fromState')
            ->with($this->callback(function (array $state): bool {
                return $state['id'] === self::REFRESH_TOKEN_ID;
            }))->willReturn($refreshToken);

        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenMock);
        $foundRefreshToken = $this->repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertEquals($refreshToken, $foundRefreshToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddAndNotFound(): void
    {
        $notFoundRefreshToken = $this->repository->findById('notoken');

        $this->assertNull($notFoundRefreshToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRevokeToken(): void
    {
        $revokedRefreshTokenMock = $this->createMock(RefreshTokenEntity::class);
        $revokedRefreshTokenMock->method('isRevoked')->willReturn(true);
        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenMock);
        $this->refreshTokenEntityMock->expects($this->once())->method('revoke');
        $this->refreshTokenEntityFactoryMock->expects($this->atLeastOnce())
            ->method('fromState')
            ->with($this->callback(function (array $state): bool {
                return $state['id'] === self::REFRESH_TOKEN_ID;
            }))
            ->willReturnOnConsecutiveCalls($this->refreshTokenEntityMock, $revokedRefreshTokenMock);

        $this->repository->revokeRefreshToken(self::REFRESH_TOKEN_ID);
        $isRevoked = $this->repository->isRefreshTokenRevoked(self::REFRESH_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(RuntimeException::class);

        $this->repository->revokeRefreshToken('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(RuntimeException::class);

        $this->repository->isRefreshTokenRevoked('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testRemoveExpired(): void
    {
        $this->repository->removeExpired();
        $notFoundRefreshToken = $this->repository->findById(self::REFRESH_TOKEN_ID);

        $this->assertNull($notFoundRefreshToken);
    }
}
