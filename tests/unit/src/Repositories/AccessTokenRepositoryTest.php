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
use Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AccessTokenRepository
 */
class AccessTokenRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'access_token_client_id';
    final public const USER_ID = 'access_token_user_id';
    final public const ACCESS_TOKEN_ID = 'access_token_id';

    protected AccessTokenRepository $repository;

    protected MockObject $moduleConfigMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $clientEntityFactoryMock;
    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $accessTokenEntityMock;
    protected MockObject $helpersMock;
    protected MockObject $dateTimeHelperMock;

    protected static bool $dbSeeded = false;
    protected ClientEntityInterface $clientEntity;
    protected array $accessTokenState;

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
    }

    protected function setUp(): void
    {
        $this->moduleConfigMock =  $this->createMock(ModuleConfig::class);
        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);

        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientEntity = ClientRepositoryTest::getClient(self::CLIENT_ID);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntity);

        $this->clientEntityFactoryMock->method('fromState')->willReturn($this->clientEntity);

        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->accessTokenEntityFactoryMock->method('fromData')->willReturn($this->accessTokenEntityMock);
        $this->accessTokenEntityFactoryMock->method('fromState')->willReturn($this->accessTokenEntityMock);

        $this->accessTokenState = [
            'id' => self::ACCESS_TOKEN_ID,
            'scopes' => '{"openid":"openid","profile":"profile"}',
            'expires_at' => date('Y-m-d H:i:s', time() - 60), // expired...
            'user_id' => 'user123',
            'client_id' => self::CLIENT_ID,
            'is_revoked' => false,
            'auth_code_id' => 'authCode123',
        ];

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(Helpers\DateTime::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);

        $database = Database::getInstance();

        $this->repository = new AccessTokenRepository(
            $this->moduleConfigMock,
            $database,
            null,
            $this->clientRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->helpersMock,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_access_token', $this->repository->getTableName());
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
        $this->accessTokenEntityMock->method('getState')->willReturn($this->accessTokenState);

        $this->repository->persistNewAccessToken($this->accessTokenEntityMock);

        $foundAccessToken = $this->repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($this->accessTokenEntityMock, $foundAccessToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddAndNotFound(): void
    {
        $notFoundAccessToken = $this->repository->findById('notoken');

        $this->assertNull($notFoundAccessToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testRevokeToken(): void
    {
        $this->accessTokenEntityMock->expects($this->once())->method('revoke');
        $state = $this->accessTokenState;
        $state['is_revoked'] = true;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('isRevoked')->willReturn(true);

        $this->repository->revokeAccessToken(self::ACCESS_TOKEN_ID);
        $isRevoked = $this->repository->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(Exception::class);

        $this->repository->revokeAccessToken('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(Exception::class);

        $this->repository->isAccessTokenRevoked('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testRemoveExpired(): void
    {
        $dateTimeMock = $this->createMock(DateTimeImmutable::class);
        $dateTimeMock->expects($this->once())->method('format')
            ->willReturn(date(DateFormatsEnum::DB_DATETIME->value));
        $this->dateTimeHelperMock->expects($this->once())->method('getUtc')
            ->willReturn($dateTimeMock);

        $this->repository->removeExpired();
        $notFoundAccessToken = $this->repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }
}
