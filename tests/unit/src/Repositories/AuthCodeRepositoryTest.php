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
use Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

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
    protected MockObject $authCodeEntityFactoryMock;
    protected MockObject $helpersMock;
    protected MockObject $dateTimeHelperMock;
    /** @var \League\OAuth2\Server\Entities\ScopeEntityInterface[]  */
    protected array $scopes;

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

        $this->scopes = [new ScopeEntity('openid')];

        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(Helpers\DateTime::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);

        $this->repository = new AuthCodeRepository(
            $this->createMock(ModuleConfig::class),
            $this->clientRepositoryMock,
            $this->authCodeEntityFactoryMock,
            $this->helpersMock,
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
        $authCode = new AuthCodeEntity(
            self::AUTH_CODE_ID,
            $this->clientEntityMock,
            $this->scopes,
            new DateTimeImmutable('yesterday', new DateTimeZone('UTC')),
            self::USER_ID,
            self::REDIRECT_URI,
        );

        $this->repository->persistNewAuthCode($authCode);

        $this->authCodeEntityFactoryMock->expects($this->once())->method('fromState')
            ->with(
                $this->callback(
                    fn(array $state): bool => $state['id'] === self::AUTH_CODE_ID,
                ),
            )
            ->willReturn($authCode);

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

        $authCode = new AuthCodeEntity(
            self::AUTH_CODE_ID,
            $this->clientEntityMock,
            $this->scopes,
            new DateTimeImmutable('yesterday', new DateTimeZone('UTC')),
            self::USER_ID,
            self::REDIRECT_URI,
        );

        $revokedAuthCode = clone $authCode;
        $revokedAuthCode->revoke();

        $callNumber = 1;
        $this->authCodeEntityFactoryMock->expects($this->exactly(2))
            ->method('fromState')
            ->with(
                $this->callback(
                    function (array $state) use (&$callNumber): bool {
                        if ($callNumber === 1) {
                            $callNumber++;
                            return $state['is_revoked'] === 0;
                        }
                        return $state['is_revoked'] === 1;
                    },
                ),
            )->willReturn($authCode, $revokedAuthCode);

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
        $dateTimeMock = $this->createMock(DateTimeImmutable::class);
        $dateTimeMock->expects($this->once())->method('format')
            ->willReturn(date(DateFormatsEnum::DB_DATETIME->value));
        $this->dateTimeHelperMock->expects($this->once())->method('getUtc')->willReturn($dateTimeMock);

        $this->repository->removeExpired();
        $notFoundAuthCode = $this->repository->findById(self::AUTH_CODE_ID);

        $this->assertNull($notFoundAuthCode);
    }
}
