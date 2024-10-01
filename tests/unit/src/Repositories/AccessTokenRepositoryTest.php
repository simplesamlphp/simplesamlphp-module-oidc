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
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
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

    protected AccessTokenRepository $repository;

    protected MockObject $moduleConfigMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $clientEntityFactoryMock;

    protected static bool $dbSeeded = false;
    protected ClientEntityInterface $clientEntity;

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

        $this->repository = new AccessTokenRepository($this->moduleConfigMock, $this->clientRepositoryMock);
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
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $accessToken = $this->repository->getNewToken(
            $this->clientEntity,
            $scopes,
            self::USER_ID,
        );
        $accessToken->setIdentifier(self::ACCESS_TOKEN_ID);
        $accessToken->setExpiryDateTime(DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc('yesterday'),
        ));

        $this->repository->persistNewAccessToken($accessToken);

        $foundAccessToken = $this->repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($accessToken, $foundAccessToken);
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
        $this->repository->removeExpired();
        $notFoundAccessToken = $this->repository->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }
}
