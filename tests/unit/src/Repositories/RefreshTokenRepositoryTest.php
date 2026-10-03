<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use PDO;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Exceptions\TokenNotFoundException;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository
 */
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


    final public const string CLIENT_ID = 'refresh_token_client_id';

    final public const string USER_ID = 'refresh_token_user_id';

    final public const string ACCESS_TOKEN_ID = 'refresh_token_access_token_id';

    final public const string REFRESH_TOKEN_ID = 'refresh_token_id';

    final public const string AUTH_CODE_ID = 'auth_code_id';


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

        $database = Database::getInstance();

        $this->repository = new RefreshTokenRepository(
            new ModuleConfig(),
            $database,
            null,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
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
            ->with(
                $this->callback(
                    fn(array $state): bool => $state['id'] === self::REFRESH_TOKEN_ID,
                ),
            )->willReturn($refreshToken);

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
            ->with($this->callback(fn(array $state): bool => $state['id'] === self::REFRESH_TOKEN_ID))
            ->willReturnOnConsecutiveCalls($this->refreshTokenEntityMock, $revokedRefreshTokenMock);

        $this->repository->revokeRefreshToken(self::REFRESH_TOKEN_ID);
        $isRevoked = $this->repository->isRefreshTokenRevoked(self::REFRESH_TOKEN_ID);

        $this->assertTrue($isRevoked);
    }


    /**
     * An access token's deletion (with its user or its client) cascades to its refresh token's row; a copy of
     * that row in the protocol cache outlives it, and is dropped -- with the refresh token answered as not
     * found -- when its access token turns out to be gone.
     */
    public function testFindByIdTreatsACachedTokenWhoseAccessTokenIsGoneAsNotFound(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('get')->willReturn([
            'id' => self::REFRESH_TOKEN_ID,
            'expires_at' => '2099-01-01 00:00:00',
            'access_token_id' => self::ACCESS_TOKEN_ID,
            'is_revoked' => false,
            'auth_code_id' => null,
        ]);
        $protocolCacheMock->expects($this->once())->method('delete');

        $this->accessTokenRepositoryMock->method('findById')->with(self::ACCESS_TOKEN_ID)->willReturn(null);
        $this->refreshTokenEntityFactoryMock->expects($this->never())->method('fromState');

        $repository = new RefreshTokenRepository(
            new ModuleConfig(),
            Database::getInstance(),
            $protocolCacheMock,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        );

        $this->assertNull($repository->findById(self::REFRESH_TOKEN_ID));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorRevokeInvalidToken(): void
    {
        $this->expectException(TokenNotFoundException::class);

        $this->repository->revokeRefreshToken('notoken');
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testErrorCheckIsRevokedInvalidToken(): void
    {
        $this->expectException(TokenNotFoundException::class);

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


    public function testGetNewRefreshTokenThrows(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Not implemented');

        $this->repository->getNewRefreshToken();
    }


    public function testPersistNewRefreshTokenThrowsIfNotRefreshTokenEntity(): void
    {
        $this->expectException(OAuthServerException::class);

        $oAuthRefreshTokenEntity = $this->createMock(RefreshTokenEntityInterface::class);

        $this->repository->persistNewRefreshToken($oAuthRefreshTokenEntity);
    }


    public function testCanRevokeByAuthCodeId(): void
    {
        $refreshToken = new RefreshTokenEntity(
            self::REFRESH_TOKEN_ID,
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
            self::AUTH_CODE_ID,
        );

        $this->repository->persistNewRefreshToken($refreshToken);

        $this->repository->revokeByAuthCodeId(self::AUTH_CODE_ID);

        $this->assertTrue($this->isRevokedOnThePrimary(self::REFRESH_TOKEN_ID));
    }


    /**
     * The token endpoint revokes what it has just issued for a code when the rest of its response fails, before a
     * database secondary may have it, and with no copy in a protocol cache (none is configured by default).
     */
    public function testRevokesByAuthCodeIdWhatWasJustIssuedBeforeASecondaryHasIt(): void
    {
        $repository = new RefreshTokenRepository(
            new ModuleConfig(),
            $this->databaseWithALaggingSecondary(),
            null,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        );
        $repository->persistNewRefreshToken(new RefreshTokenEntity(
            'just_issued_refresh_token_id',
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
            'just_issued_auth_code_id',
        ));

        $repository->revokeByAuthCodeId('just_issued_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('just_issued_refresh_token_id'));
    }


    /**
     * Every refresh token issued for the code is revoked, and no refresh token issued for another code.
     */
    public function testRevokesByAuthCodeIdEveryRefreshTokenOfThatCodeAndNoOther(): void
    {
        $authCodeIdsByTokenId = [
            'every_token_first_refresh_token_id' => 'every_refresh_token_auth_code_id',
            'every_token_second_refresh_token_id' => 'every_refresh_token_auth_code_id',
            'every_token_other_refresh_token_id' => 'every_refresh_token_other_auth_code_id',
        ];

        foreach ($authCodeIdsByTokenId as $tokenId => $authCodeId) {
            $this->repository->persistNewRefreshToken(new RefreshTokenEntity(
                $tokenId,
                new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
                $this->accessTokenMock,
                $authCodeId,
            ));
        }

        $this->repository->revokeByAuthCodeId('every_refresh_token_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('every_token_first_refresh_token_id'));
        $this->assertTrue($this->isRevokedOnThePrimary('every_token_second_refresh_token_id'));
        $this->assertFalse($this->isRevokedOnThePrimary('every_token_other_refresh_token_id'));
    }


    /**
     * Without a protocol cache (none is configured by default) there is nothing to cache the revoked rows in, so
     * nothing is read: the one UPDATE is all.
     */
    public function testRevokingByAuthCodeIdWithoutACacheReadsNothing(): void
    {
        $this->repository->persistNewRefreshToken(new RefreshTokenEntity(
            'read_nothing_refresh_token_id',
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
            'read_nothing_refresh_token_auth_code_id',
        ));

        $database = Database::getInstance();
        $databaseMock = $this->createMock(Database::class);
        $databaseMock->method('applyPrefix')->willReturnCallback($database->applyPrefix(...));
        $databaseMock->expects($this->once())->method('write')->willReturnCallback($database->write(...));
        $databaseMock->expects($this->never())->method('readPrimary');
        $databaseMock->expects($this->never())->method('read');

        (new RefreshTokenRepository(
            new ModuleConfig(),
            $databaseMock,
            null,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        ))->revokeByAuthCodeId('read_nothing_refresh_token_auth_code_id');

        $this->assertTrue($this->isRevokedOnThePrimary('read_nothing_refresh_token_id'));
    }


    /**
     * With a protocol cache, the revoked row is cached in place of any copy, so that a valid one cached by an
     * earlier lookup does not outlive the revocation. The cache is not asked first, so the row is cached where
     * there was no copy too. It is read from the primary, since the token may be too new for a secondary.
     */
    public function testRevokingByAuthCodeIdCachesTheRevokedRow(): void
    {
        $this->repository->persistNewRefreshToken(new RefreshTokenEntity(
            'cached_refresh_token_id',
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
            'cached_auth_code_id',
        ));

        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('get')->willReturn(null);
        $protocolCacheMock->expects($this->never())->method('delete');
        $protocolCacheMock->expects($this->once())->method('set')->with(
            $this->callback(
                fn(array $row): bool => $row['id'] === 'cached_refresh_token_id' && (bool)$row['is_revoked'],
            ),
            $this->callback(fn(mixed $ttl): bool => is_int($ttl) && $ttl > 0),
            'phpunit_oidc_refresh_token_cached_refresh_token_id',
        );

        (new RefreshTokenRepository(
            new ModuleConfig(),
            $this->databaseWithALaggingSecondary(),
            $protocolCacheMock,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        ))->revokeByAuthCodeId('cached_auth_code_id');
    }


    /**
     * A refresh token may be looked up before a database secondary has it, with no copy in a protocol cache (none is
     * configured by default).
     */
    public function testFindsAJustIssuedRefreshTokenBeforeASecondaryHasIt(): void
    {
        $refreshToken = new RefreshTokenEntity(
            'found_on_the_primary_refresh_token_id',
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
        );
        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenMock);
        $this->refreshTokenEntityFactoryMock->expects($this->once())->method('fromState')
            ->with($this->callback(
                fn(array $state): bool => $state['id'] === 'found_on_the_primary_refresh_token_id',
            ))
            ->willReturn($refreshToken);

        $repository = new RefreshTokenRepository(
            new ModuleConfig(),
            $this->databaseWithALaggingSecondary(),
            null,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        );
        $repository->persistNewRefreshToken($refreshToken);

        $this->assertSame($refreshToken, $repository->findById('found_on_the_primary_refresh_token_id'));
    }


    /**
     * The refresh token grant refuses a refresh token by its revocation, which a database secondary may not have
     * yet. The token is read from the primary, and not only when a secondary has no copy of it.
     */
    public function testARefreshTokenRevokedOnThePrimaryIsRevokedWhileASecondaryStillHasItValid(): void
    {
        $tokenId = 'revoked_on_the_primary_refresh_token_id';
        $this->repository->persistNewRefreshToken(new RefreshTokenEntity(
            $tokenId,
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            $this->accessTokenMock,
        ));
        $rowsBeforeTheRevocation = $this->rowsWithId('phpunit_oidc_refresh_token', $tokenId);
        Database::getInstance()->write(
            'UPDATE phpunit_oidc_refresh_token SET is_revoked = :revoked WHERE id = :id',
            ['revoked' => [true, PDO::PARAM_BOOL], 'id' => $tokenId],
        );

        $validRefreshTokenMock = $this->createMock(RefreshTokenEntity::class);
        $validRefreshTokenMock->method('isRevoked')->willReturn(false);
        $revokedRefreshTokenMock = $this->createMock(RefreshTokenEntity::class);
        $revokedRefreshTokenMock->method('isRevoked')->willReturn(true);
        $this->accessTokenRepositoryMock->method('findById')->willReturn($this->accessTokenMock);
        $this->refreshTokenEntityFactoryMock->method('fromState')->willReturnCallback(
            fn(array $state): RefreshTokenEntity => (bool)$state['is_revoked'] ?
                $revokedRefreshTokenMock :
                $validRefreshTokenMock,
        );

        $repository = new RefreshTokenRepository(
            new ModuleConfig(),
            $this->databaseWithAStaleSecondary($rowsBeforeTheRevocation),
            null,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            new Helpers(),
        );

        $this->assertTrue($repository->isRefreshTokenRevoked($tokenId));
    }


    protected function isRevokedOnThePrimary(string $tokenId): bool
    {
        return (bool)Database::getInstance()->readPrimary(
            'SELECT is_revoked FROM phpunit_oidc_refresh_token WHERE id = :id',
            ['id' => $tokenId],
        )->fetchColumn();
    }
}
