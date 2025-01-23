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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

#[CoversClass(AccessTokenRepository::class)]
class AccessTokenRepositoryTest extends TestCase
{
    final public const CLIENT_ID = 'access_token_client_id';
    final public const USER_ID = 'access_token_user_id';
    final public const ACCESS_TOKEN_ID = 'access_token_id';
    final public const AUTH_CODE_ID = 'auth_code_id';

    protected MockObject $moduleConfigMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $clientEntityFactoryMock;
    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $accessTokenEntityMock;
    protected MockObject $helpersMock;
    protected MockObject $dateTimeHelperMock;

    protected static bool $dbSeeded = false;
    protected MockObject $clientEntityMock;
    protected array $accessTokenState;
    protected Database $database;
    protected MockObject $protocolCacheMock;

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
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->clientEntityFactoryMock->method('fromState')->willReturn($this->clientEntityMock);

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
            'auth_code_id' => self::AUTH_CODE_ID,
        ];

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(Helpers\DateTime::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);

        $this->database = Database::getInstance();
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
    }

    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?Database $database = null,
        ?ProtocolCache $protocolCache = null,
        ?ClientRepository $clientRepository = null,
        ?AccessTokenEntityFactory $accessTokenEntityFactory = null,
        ?Helpers $helpers = null,
    ): AccessTokenRepository {
        $moduleConfig ??= $this->moduleConfigMock;
        $database ??= $this->database;
        $protocolCache ??= $this->protocolCacheMock;
        $clientRepository ??= $this->clientRepositoryMock;
        $accessTokenEntityFactory ??= $this->accessTokenEntityFactoryMock;
        $helpers ??= $this->helpersMock;

        return new AccessTokenRepository(
            $moduleConfig,
            $database,
            $protocolCache,
            $clientRepository,
            $accessTokenEntityFactory,
            $helpers,
        );
    }

    public function testGetTableName(): void
    {
        $this->assertSame('phpunit_oidc_access_token', $this->sut()->getTableName());
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
        $this->accessTokenEntityMock->method('getExpiryDateTime')
            ->willReturn(new DateTimeImmutable());

        $sut = $this->sut();
        $sut->persistNewAccessToken($this->accessTokenEntityMock);

        $foundAccessToken = $sut->findById(self::ACCESS_TOKEN_ID);

        $this->assertEquals($this->accessTokenEntityMock, $foundAccessToken);
    }

    public function testPersistNewAccessTokenThrowsIfNotAccessTokenEntity(): void
    {
        $oAuthAccessTokenEntity = $this->createMock(\League\OAuth2\Server\Entities\AccessTokenEntityInterface::class);

        $this->expectException(Error::class);
        $this->expectExceptionMessage('Invalid');

        $this->sut()->persistNewAccessToken($oAuthAccessTokenEntity);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddAndNotFound(): void
    {
        $notFoundAccessToken = $this->sut()->findById('notoken');

        $this->assertNull($notFoundAccessToken);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testRevokeToken(): void
    {
        $this->accessTokenEntityMock->expects($this->once())->method('revoke');
        $this->accessTokenEntityMock->method('getExpiryDateTime')
            ->willReturn(new DateTimeImmutable());

        $state = $this->accessTokenState;
        $state['is_revoked'] = true;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('isRevoked')->willReturn(true);

        $sut = $this->sut();
        $sut->revokeAccessToken(self::ACCESS_TOKEN_ID);
        $isRevoked = $sut->isAccessTokenRevoked(self::ACCESS_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(Exception::class);

        $this->sut()->revokeAccessToken('notoken');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(Exception::class);

        $this->sut()->isAccessTokenRevoked('notoken');
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

        $sut = $this->sut();
        $sut->removeExpired();
        $notFoundAccessToken = $sut->findById(self::ACCESS_TOKEN_ID);

        $this->assertNull($notFoundAccessToken);
    }

    public function testCanGetNewToken()
    {
        $this->accessTokenEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($this->accessTokenEntityMock);

        $this->assertInstanceOf(
            AccessTokenEntityInterface::class,
            $this->sut()->getNewToken(
                $this->clientEntityMock,
                [],
                'userId',
                'authCodeId',
                [],
                'id',
                new DateTimeImmutable(),
            ),
        );
    }

    public function testCanGetNewTokenForEmptyUserId(): void
    {
        $this->accessTokenEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($this->accessTokenEntityMock);

        $this->assertInstanceOf(
            AccessTokenEntityInterface::class,
            $this->sut()->getNewToken(
                $this->clientEntityMock,
                [],
                '',
                'authCodeId',
                [],
                'id',
                new DateTimeImmutable(),
            ),
        );
    }

    public function testCanGetNewTokenThrowsForEmptyId(): void
    {
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Invalid');

        $this->sut()->getNewToken(
            $this->clientEntityMock,
            [],
            '',
            'authCodeId',
            [],
            null,
            new DateTimeImmutable(),
        );
    }

    public function testCanRevokeByAuthCodeId(): void
    {
        $this->accessTokenEntityMock->method('getState')->willReturn($this->accessTokenState);
        $this->accessTokenEntityMock->method('getExpiryDateTime')
            ->willReturn(new DateTimeImmutable());

        $this->accessTokenEntityMock->expects($this->once())->method('revoke');

        $sut = $this->sut();
        $sut->persistNewAccessToken($this->accessTokenEntityMock);

        $sut->revokeByAuthCodeId(self::AUTH_CODE_ID);
    }
}
