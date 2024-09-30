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
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AuthCodeRepository
 */
class AuthCodeRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'auth_code_client_id';
    final public const USER_ID = 'auth_code_user_id';
    final public const AUTH_CODE_ID = 'auth_code_id';
    final public const REDIRECT_URI = 'http://localhost/redirect';

    protected AuthCodeRepository $repository;
    protected MockObject $clientEntityMock;
    protected MockObject $clientRepositoryMock;

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
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->repository = new AuthCodeRepository(
            $this->createMock(ModuleConfig::class),
            $this->clientRepositoryMock,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_auth_code', $this->repository->getTableName());
    }

    /**
     * @throws \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @throws \SimpleSAML\Error\Error
     * @throws \JsonException
     * @throws \Exception
     */
    public function testAddAndFound(): void
    {
        $scopes = [
            ScopeEntity::fromData('openid'),
        ];

        $authCode = $this->repository->getNewAuthCode();

        $authCode->setIdentifier(self::AUTH_CODE_ID);
        $authCode->setClient($this->clientEntityMock);
        $authCode->setUserIdentifier(self::USER_ID);
        $authCode->setExpiryDateTime(DateTimeImmutable::createFromMutable(TimestampGenerator::utc('yesterday')));
        $authCode->setRedirectUri(self::REDIRECT_URI);
        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        $this->repository->persistNewAuthCode($authCode);

        $foundAuthCode = $this->repository->findById(self::AUTH_CODE_ID);

        $this->assertEquals($authCode, $foundAuthCode);
    }

    /**
     * @throws \Exception
     */
    public function testAddAndNotFound(): void
    {
        $notFoundAuthCode = $this->repository->findById('nocode');

        $this->assertNull($notFoundAuthCode);
    }

    /**
     * @throws \JsonException
     * @throws \Exception
     */
    public function testRevokeCode(): void
    {
        $this->repository->revokeAuthCode(self::AUTH_CODE_ID);
        $isRevoked = $this->repository->isAuthCodeRevoked(self::AUTH_CODE_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws \JsonException
     */
    public function testErrorRevokeInvalidAuthCode(): void
    {
        $this->expectException(Exception::class);

        $this->repository->revokeAuthCode('nocode');
    }

    public function testErrorCheckIsRevokedInvalidAuthCode(): void
    {
        $this->expectException(Exception::class);

        $this->repository->isAuthCodeRevoked('nocode');
    }

    /**
     * @throws \Exception
     */
    public function testRemoveExpired(): void
    {
        $this->repository->removeExpired();
        $notFoundAuthCode = $this->repository->findById(self::AUTH_CODE_ID);

        $this->assertNull($notFoundAuthCode);
    }
}
