<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use PDO;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
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
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

#[CoversClass(AccessTokenRepository::class)]
#[AllowMockObjectsWithoutExpectations]
class AccessTokenRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


    final public const string CLIENT_ID = 'access_token_client_id';

    final public const string USER_ID = 'access_token_user_id';

    final public const string ACCESS_TOKEN_ID = 'access_token_id';

    final public const string AUTH_CODE_ID = 'auth_code_id';


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
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);
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
     * A client's deletion cascades to its tokens' rows; a copy of such a row in the protocol cache outlives that,
     * and is dropped -- with the token answered as not found -- when its client turns out to be gone.
     */
    public function testFindByIdTreatsACachedTokenWhoseClientIsGoneAsNotFound(): void
    {
        $this->protocolCacheMock->method('get')->willReturn($this->accessTokenState);
        $this->protocolCacheMock->expects($this->once())->method('delete');

        $clientRepositoryMock = $this->createMock(ClientRepository::class);
        $clientRepositoryMock->method('findById')->willReturn(null);
        $this->accessTokenEntityFactoryMock->expects($this->never())->method('fromState');

        $this->assertNull($this->sut(clientRepository: $clientRepositoryMock)->findById(self::ACCESS_TOKEN_ID));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(TokenNotFoundException::class);

        $this->sut()->revokeAccessToken('notoken');
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(TokenNotFoundException::class);

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

        $sut = $this->sut();
        $sut->persistNewAccessToken($this->accessTokenEntityMock);

        $sut->revokeByAuthCodeId(self::AUTH_CODE_ID);

        $this->assertTrue($this->isRevokedOnThePrimary(self::ACCESS_TOKEN_ID));
    }


    /**
     * The token endpoint revokes what it has just issued for a code when the rest of its response fails, before a
     * database secondary may have it, and with no copy in a protocol cache (none is configured by default).
     */
    public function testRevokesByAuthCodeIdWhatWasJustIssuedBeforeASecondaryHasIt(): void
    {
        $state = [
            'id' => 'just_issued_access_token_id',
            'auth_code_id' => 'just_issued_auth_code_id',
        ] + $this->accessTokenState;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn(new DateTimeImmutable());

        $sut = new AccessTokenRepository(
            $this->moduleConfigMock,
            $this->databaseWithALaggingSecondary(),
            null,
            $this->clientRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->helpersMock,
        );
        $sut->persistNewAccessToken($this->accessTokenEntityMock);

        $sut->revokeByAuthCodeId('just_issued_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('just_issued_access_token_id'));
    }


    /**
     * Every token issued for the code is revoked, and no token issued for another code.
     */
    public function testRevokesByAuthCodeIdEveryTokenOfThatCodeAndNoOther(): void
    {
        $sut = new AccessTokenRepository(
            $this->moduleConfigMock,
            $this->database,
            null,
            $this->clientRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->helpersMock,
        );

        $authCodeIdsByTokenId = [
            'every_token_first_access_token_id' => 'every_token_auth_code_id',
            'every_token_second_access_token_id' => 'every_token_auth_code_id',
            'every_token_other_access_token_id' => 'every_token_other_auth_code_id',
        ];

        foreach ($authCodeIdsByTokenId as $tokenId => $authCodeId) {
            $accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);
            $accessTokenEntityMock->method('getState')
                ->willReturn(['id' => $tokenId, 'auth_code_id' => $authCodeId] + $this->accessTokenState);
            $sut->persistNewAccessToken($accessTokenEntityMock);
        }

        $sut->revokeByAuthCodeId('every_token_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('every_token_first_access_token_id'));
        $this->assertTrue($this->isRevokedOnThePrimary('every_token_second_access_token_id'));
        $this->assertFalse($this->isRevokedOnThePrimary('every_token_other_access_token_id'));
    }


    /**
     * Without a protocol cache (none is configured by default) there is nothing to cache the revoked rows in, so
     * nothing is read: the one UPDATE is all.
     */
    public function testRevokingByAuthCodeIdWithoutACacheReadsNothing(): void
    {
        $state = [
            'id' => 'read_nothing_access_token_id',
            'auth_code_id' => 'read_nothing_auth_code_id',
        ] + $this->accessTokenState;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn(new DateTimeImmutable());
        $this->sut()->persistNewAccessToken($this->accessTokenEntityMock);

        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback($this->database->applyPrefix(...));
        $databaseMock->expects($this->once())->method('write')->willReturnCallback($this->database->write(...));
        $databaseMock->expects($this->never())->method('readPrimary');
        $databaseMock->expects($this->never())->method('read');

        (new AccessTokenRepository(
            $this->moduleConfigMock,
            $databaseMock,
            null,
            $this->clientRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->helpersMock,
        ))->revokeByAuthCodeId('read_nothing_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('read_nothing_access_token_id'));
    }


    /**
     * With a protocol cache, the revoked row is cached in place of any copy, so that a valid one cached by an
     * earlier lookup does not outlive the revocation. The cache is not asked first, so the row is cached where
     * there was no copy too. It is read from the primary, since the token may be too new for a secondary.
     */
    public function testRevokingByAuthCodeIdCachesTheRevokedRow(): void
    {
        $state = [
            'id' => 'cached_access_token_id',
            'auth_code_id' => 'cached_auth_code_id',
            'expires_at' => gmdate('Y-m-d H:i:s', time() + 3600),
        ] + $this->accessTokenState;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn(new DateTimeImmutable());
        $this->sut()->persistNewAccessToken($this->accessTokenEntityMock);

        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('get')->willReturn(null);
        $protocolCacheMock->expects($this->never())->method('delete');
        $protocolCacheMock->expects($this->once())->method('set')->with(
            $this->callback(
                fn(array $row): bool => $row['id'] === 'cached_access_token_id' && (bool)$row['is_revoked'],
            ),
            $this->callback(fn(mixed $ttl): bool => is_int($ttl) && $ttl > 0),
            'phpunit_oidc_access_token_cached_access_token_id',
        );

        $this->sut(
            database: $this->databaseWithALaggingSecondary(),
            protocolCache: $protocolCacheMock,
            helpers: new Helpers(),
        )->revokeByAuthCodeId('cached_auth_code_id');
    }


    /**
     * A resource endpoint reads a token moments after the token endpoint issued it, before a database secondary may
     * have it, and with no copy in a protocol cache (none is configured by default).
     */
    public function testFindsAJustIssuedTokenBeforeASecondaryHasIt(): void
    {
        $state = [
            'id' => 'found_on_the_primary_access_token_id',
            'auth_code_id' => 'found_on_the_primary_auth_code_id',
        ] + $this->accessTokenState;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn(new DateTimeImmutable());
        $accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $accessTokenEntityFactoryMock->expects($this->once())->method('fromState')
            ->with($this->callback(fn(array $row): bool => $row['id'] === 'found_on_the_primary_access_token_id'))
            ->willReturn($this->accessTokenEntityMock);

        $sut = new AccessTokenRepository(
            $this->moduleConfigMock,
            $this->databaseWithALaggingSecondary(),
            null,
            $this->clientRepositoryMock,
            $accessTokenEntityFactoryMock,
            $this->helpersMock,
        );
        $sut->persistNewAccessToken($this->accessTokenEntityMock);

        $this->assertSame($this->accessTokenEntityMock, $sut->findById('found_on_the_primary_access_token_id'));
    }


    /**
     * A resource endpoint accepts a token only if it is not revoked, which a database secondary may not have yet.
     * The token is read from the primary, and not only when a secondary has no copy of it.
     */
    public function testATokenRevokedOnThePrimaryIsRevokedWhileASecondaryStillHasItValid(): void
    {
        $tokenId = 'revoked_on_the_primary_access_token_id';
        $state = [
            'id' => $tokenId,
            'auth_code_id' => 'revoked_on_the_primary_auth_code_id',
        ] + $this->accessTokenState;
        $this->accessTokenEntityMock->method('getState')->willReturn($state);
        $this->accessTokenEntityMock->method('getExpiryDateTime')->willReturn(new DateTimeImmutable());
        $this->sut()->persistNewAccessToken($this->accessTokenEntityMock);
        $rowsBeforeTheRevocation = $this->rowsWithId('phpunit_oidc_access_token', $tokenId);
        $this->database->write(
            'UPDATE phpunit_oidc_access_token SET is_revoked = :revoked WHERE id = :id',
            ['revoked' => [true, PDO::PARAM_BOOL], 'id' => $tokenId],
        );

        $validAccessTokenMock = $this->createMock(AccessTokenEntity::class);
        $validAccessTokenMock->method('isRevoked')->willReturn(false);
        $revokedAccessTokenMock = $this->createMock(AccessTokenEntity::class);
        $revokedAccessTokenMock->method('isRevoked')->willReturn(true);
        $accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $accessTokenEntityFactoryMock->method('fromState')->willReturnCallback(
            fn(array $row): AccessTokenEntity => (bool)$row['is_revoked'] ?
                $revokedAccessTokenMock :
                $validAccessTokenMock,
        );

        $sut = new AccessTokenRepository(
            $this->moduleConfigMock,
            $this->databaseWithAStaleSecondary($rowsBeforeTheRevocation),
            null,
            $this->clientRepositoryMock,
            $accessTokenEntityFactoryMock,
            $this->helpersMock,
        );

        $this->assertTrue($sut->isAccessTokenRevoked($tokenId));
    }


    protected function isRevokedOnThePrimary(string $tokenId): bool
    {
        return (bool)$this->database->readPrimary(
            'SELECT is_revoked FROM phpunit_oidc_access_token WHERE id = :id',
            ['id' => $tokenId],
        )->fetchColumn();
    }
}
