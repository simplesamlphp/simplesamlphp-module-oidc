<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Repositories;

use DateTimeImmutable;
use DateTimeZone;
use Exception;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use PDO;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Codebooks\DateFormatsEnum;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AuthCodeEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

/**
 * @covers \SimpleSAML\Module\oidc\Repositories\AuthCodeRepository
 */
#[AllowMockObjectsWithoutExpectations]
class AuthCodeRepositoryTest extends TestCase
{
    use LaggingSecondaryTestTrait;


    final public const string CLIENT_ID = 'auth_code_client_id';

    final public const string USER_ID = 'auth_code_user_id';

    final public const string AUTH_CODE_ID = 'auth_code_id';

    final public const string REDIRECT_URI = 'http://localhost/redirect';


    protected AuthCodeRepository $repository;

    protected MockObject $clientEntityMock;

    protected MockObject $clientRepositoryMock;

    protected MockObject $authCodeEntityFactoryMock;

    protected MockObject $helpersMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $protocolCacheMock;

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
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientEntityMock->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->scopes = [new ScopeEntity('openid')];

        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);

        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);

        $database = Database::getInstance();

        $this->repository = new AuthCodeRepository(
            $this->moduleConfigMock,
            $database,
            $this->protocolCacheMock,
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
     * The token endpoint reads a code moments after the authorization endpoint wrote it, before a database secondary
     * may have it, and with no copy in a protocol cache (none is configured by default).
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     * @throws \Exception
     */
    public function testFindsAJustIssuedCodeBeforeASecondaryHasIt(): void
    {
        $authCode = new AuthCodeEntity(
            'found_on_the_primary_auth_code_id',
            $this->clientEntityMock,
            $this->scopes,
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            self::USER_ID,
            self::REDIRECT_URI,
        );
        $this->authCodeEntityFactoryMock->expects($this->once())->method('fromState')
            ->with($this->callback(fn(array $state): bool => $state['id'] === 'found_on_the_primary_auth_code_id'))
            ->willReturn($authCode);

        $repository = $this->uncachedRepositoryOver($this->databaseWithALaggingSecondary());
        $repository->persistNewAuthCode($authCode);

        $this->assertSame($authCode, $repository->findById('found_on_the_primary_auth_code_id'));
    }


    /**
     * The token endpoint refuses a replayed code by its revocation, which a database secondary may not have yet. The
     * code is read from the primary, and not only when a secondary has no copy of it.
     *
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     * @throws \Exception
     */
    public function testACodeRevokedOnThePrimaryIsRevokedWhileASecondaryStillHasItValid(): void
    {
        $codeId = 'revoked_on_the_primary_auth_code_id';
        $authCode = new AuthCodeEntity(
            $codeId,
            $this->clientEntityMock,
            $this->scopes,
            new DateTimeImmutable('tomorrow', new DateTimeZone('UTC')),
            self::USER_ID,
            self::REDIRECT_URI,
        );
        $revokedAuthCode = clone $authCode;
        $revokedAuthCode->revoke();
        $this->authCodeEntityFactoryMock->method('fromState')->willReturnCallback(
            fn(array $state): AuthCodeEntity => (bool)$state['is_revoked'] ? $revokedAuthCode : $authCode,
        );

        $this->repository->persistNewAuthCode($authCode);
        $rowsBeforeTheRevocation = $this->rowsWithId('phpunit_oidc_auth_code', $codeId);
        Database::getInstance()->write(
            'UPDATE phpunit_oidc_auth_code SET is_revoked = :revoked WHERE id = :id',
            ['revoked' => [true, PDO::PARAM_BOOL], 'id' => $codeId],
        );

        $this->assertTrue(
            $this->uncachedRepositoryOver($this->databaseWithAStaleSecondary($rowsBeforeTheRevocation))
                ->isAuthCodeRevoked($codeId),
        );
    }


    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     */
    public function testConsumePreAuthorizedCodeReturnsTrueOnlyOnce(): void
    {
        $codeId = 'pre_authorized_code_to_consume';
        $now = new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC'));
        $authCode = new AuthCodeEntity(
            $codeId,
            $this->clientEntityMock,
            $this->scopes,
            $now->modify('+1 hour'),
            self::USER_ID,
            self::REDIRECT_URI,
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
            txCode: '1234',
        );

        $this->dateTimeHelperMock->method('getUtc')->willReturn($now);
        $this->protocolCacheMock->expects($this->exactly(2))
            ->method('delete')
            ->with('phpunit_oidc_auth_code_' . $codeId);

        $this->repository->persistNewAuthCode($authCode);

        $this->assertTrue($this->repository->consumePreAuthorizedCode($codeId));
        $this->assertFalse($this->repository->consumePreAuthorizedCode($codeId));
    }


    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     */
    public function testConsumePreAuthorizedCodeDoesNotConsumeStandardAuthorizationCode(): void
    {
        $codeId = 'standard_authorization_code_not_to_consume';
        $now = new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC'));
        $authCode = new AuthCodeEntity(
            $codeId,
            $this->clientEntityMock,
            $this->scopes,
            $now->modify('+1 hour'),
            self::USER_ID,
            self::REDIRECT_URI,
        );

        $this->dateTimeHelperMock->method('getUtc')->willReturn($now);
        $this->repository->persistNewAuthCode($authCode);

        $this->assertFalse($this->repository->consumePreAuthorizedCode($codeId));
    }


    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Error\Error
     */
    public function testConsumePreAuthorizedCodeRejectsCodeExpiredAtConsumptionTime(): void
    {
        $codeId = 'expired_pre_authorized_code_not_to_consume';
        $now = new DateTimeImmutable('2026-01-01 00:00:00', new DateTimeZone('UTC'));
        $authCode = new AuthCodeEntity(
            $codeId,
            $this->clientEntityMock,
            $this->scopes,
            $now->modify('-1 second'),
            self::USER_ID,
            self::REDIRECT_URI,
            flowTypeEnum: FlowTypeEnum::VciPreAuthorizedCode,
        );

        $this->dateTimeHelperMock->method('getUtc')->willReturn($now);
        $this->repository->persistNewAuthCode($authCode);

        $this->assertFalse($this->repository->consumePreAuthorizedCode($codeId));
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


    public function testGetNewAuthCodeThrows(): void
    {
        $this->expectException(RuntimeException::class);

        $this->repository->getNewAuthCode();
    }


    public function testPersistNewAuthCodeThrowsIfNotAuthCodeEntity(): void
    {
        $this->expectException(Error::class);
        $this->expectExceptionMessage('Invalid');

        $this->repository->persistNewAuthCode(
            $this->createMock(AuthCodeEntityInterface::class),
        );
    }


    protected function uncachedRepositoryOver(Database $database): AuthCodeRepository
    {
        return new AuthCodeRepository(
            $this->moduleConfigMock,
            $database,
            null,
            $this->clientRepositoryMock,
            $this->authCodeEntityFactoryMock,
            $this->helpersMock,
        );
    }
}
