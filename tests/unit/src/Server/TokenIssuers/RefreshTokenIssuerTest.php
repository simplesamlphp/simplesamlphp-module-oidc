<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\TokenIssuers;

use DateInterval;
use DateTimeImmutable;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Random;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use Stringable;

/**
 * RefreshTokenIssuer::issue() draws an identifier from Helpers::random(), builds the entity through
 * RefreshTokenEntityFactory::fromData() and persists it through RefreshTokenRepository, trying again with a fresh
 * identifier when persistence reports a UniqueTokenIdentifierConstraintViolationException, up to the number of
 * attempts the caller allows (AbstractTokenIssuer::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS, five, by default; the
 * three grants pass League's ten). An access token of another League implementation is refused first.
 */
#[CoversClass(RefreshTokenIssuer::class)]
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenIssuerTest extends TestCase
{
    private const string ACCESS_TOKEN_ID = 'access-token-id';

    private const string AUTH_CODE_ID = 'auth-code-id';


    private Helpers&MockObject $helpersMock;

    private Random&MockObject $randomMock;

    private RefreshTokenRepository&MockObject $refreshTokenRepositoryMock;

    private RefreshTokenEntityFactory&MockObject $refreshTokenEntityFactoryMock;

    private LoggerService&MockObject $loggerMock;

    private AccessTokenEntity&MockObject $accessTokenMock;

    private RefreshTokenEntity&MockObject $refreshTokenMock;

    /**
     * Every error record the logger received, as [message, context] pairs, once captureErrorLogs() is on.
     *
     * @var list<array{0: string, 1: array}>
     */
    private array $errorLogs = [];


    protected function setUp(): void
    {
        $this->randomMock = $this->createMock(Random::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('random')->willReturn($this->randomMock);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepository::class);
        $this->refreshTokenEntityFactoryMock = $this->createMock(RefreshTokenEntityFactory::class);
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getIdentifier')->willReturn(self::ACCESS_TOKEN_ID);
        $this->refreshTokenMock = $this->createMock(RefreshTokenEntity::class);
    }


    private function sut(): RefreshTokenIssuer
    {
        return new RefreshTokenIssuer(
            $this->helpersMock,
            $this->refreshTokenRepositoryMock,
            $this->refreshTokenEntityFactoryMock,
            $this->loggerMock,
        );
    }


    /**
     * The entity factory takes the module's AccessTokenEntityInterface, so an access token which implements
     * League's interface only is refused before an identifier is drawn.
     */
    public function testRefusesAnAccessTokenWhichIsNotTheModulesEntity(): void
    {
        $this->randomMock->expects($this->never())->method('getIdentifier');
        $this->refreshTokenEntityFactoryMock->expects($this->never())->method('fromData');

        try {
            $this->sut()->issue(
                $this->createMock(OAuth2AccessTokenEntityInterface::class),
                new DateInterval('PT1H'),
            );
        } catch (OidcServerException $exception) {
            $this->assertServerError($exception, 'Unexpected access token entity type.');

            return;
        }

        $this->fail('The access token was accepted.');
    }


    /**
     * The entity is built from the drawn identifier, an expiry the lifetime away from now, the access token and
     * the authorization code identifier, not revoked, and is persisted and returned as it came from the factory.
     */
    #[DataProvider('authCodeIdProvider')]
    public function testIssuesARefreshTokenFromAFreshIdentifierAndPersistsIt(?string $authCodeId): void
    {
        $lifetime = new DateInterval('PT1H');
        $this->randomMock->expects($this->once())->method('getIdentifier')->willReturn('refresh-token-id');
        $this->refreshTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->with(
                'refresh-token-id',
                $this->callback(
                    static fn(DateTimeImmutable $expiry): bool => abs(
                        $expiry->getTimestamp() - (new DateTimeImmutable())->add($lifetime)->getTimestamp(),
                    ) <= 1,
                ),
                $this->identicalTo($this->accessTokenMock),
                $authCodeId,
                false,
            )
            ->willReturn($this->refreshTokenMock);
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('persistNewRefreshToken')
            ->with($this->identicalTo($this->refreshTokenMock));
        $this->loggerMock->expects($this->never())->method('error');

        $this->assertSame(
            $this->refreshTokenMock,
            $authCodeId === null
                ? $this->sut()->issue($this->accessTokenMock, $lifetime)
                : $this->sut()->issue($this->accessTokenMock, $lifetime, $authCodeId),
        );
    }


    public static function authCodeIdProvider(): array
    {
        return [
            'from an authorization code' => [self::AUTH_CODE_ID],
            'without one, the default' => [null],
        ];
    }


    /**
     * A colliding identifier is not an error: the next attempt draws a fresh one, builds a new entity from it and
     * the same access token and code identifier, persists that one, and nothing is logged.
     */
    public function testTriesAgainWithAFreshIdentifierWhenTheFirstOneCollides(): void
    {
        $lifetime = new DateInterval('PT1H');
        $firstRefreshToken = $this->createMock(RefreshTokenEntity::class);
        $secondRefreshToken = $this->createMock(RefreshTokenEntity::class);
        $persisted = [];
        $this->randomMock->expects($this->exactly(2))
            ->method('getIdentifier')
            ->willReturnOnConsecutiveCalls('colliding-id', 'fresh-id');
        $this->refreshTokenEntityFactoryMock->expects($this->exactly(2))
            ->method('fromData')
            ->willReturnCallback(
                function (
                    string $id,
                    DateTimeImmutable $expiry,
                    OAuth2AccessTokenEntityInterface $accessToken,
                    ?string $authCodeId,
                    bool $isRevoked,
                ) use (
                    $lifetime,
                    $firstRefreshToken,
                    $secondRefreshToken,
                ): RefreshTokenEntity {
                    $this->assertLessThanOrEqual(
                        1,
                        abs($expiry->getTimestamp() - (new DateTimeImmutable())->add($lifetime)->getTimestamp()),
                    );
                    $this->assertSame($this->accessTokenMock, $accessToken);
                    $this->assertSame(self::AUTH_CODE_ID, $authCodeId);
                    $this->assertFalse($isRevoked);

                    return match ($id) {
                        'colliding-id' => $firstRefreshToken,
                        'fresh-id' => $secondRefreshToken,
                    };
                },
            );
        $this->refreshTokenRepositoryMock->expects($this->exactly(2))
            ->method('persistNewRefreshToken')
            ->willReturnCallback(
                static function (RefreshTokenEntity $refreshToken) use ($firstRefreshToken, &$persisted): void {
                    $persisted[] = $refreshToken;
                    if ($refreshToken === $firstRefreshToken) {
                        throw UniqueTokenIdentifierConstraintViolationException::create();
                    }
                },
            );
        $this->loggerMock->expects($this->never())->method('error');

        $this->assertSame(
            $secondRefreshToken,
            $this->sut()->issue($this->accessTokenMock, $lifetime, self::AUTH_CODE_ID),
        );
        $this->assertSame([$firstRefreshToken, $secondRefreshToken], $persisted);
    }


    /**
     * When every allowed attempt collides, the last collision is logged and rethrown as it is. The context
     * reports the attempt counter as it stands then, 0, not the limit the call started from.
     */
    public function testGivesUpAfterTheAllowedAttemptsAndRethrowsTheLastCollision(): void
    {
        $collisions = [];
        $this->randomMock->expects($this->exactly(3))->method('getIdentifier')->willReturn('colliding-id');
        $this->refreshTokenEntityFactoryMock->expects($this->exactly(3))
            ->method('fromData')
            ->willReturn($this->refreshTokenMock);
        $this->refreshTokenRepositoryMock->expects($this->exactly(3))
            ->method('persistNewRefreshToken')
            ->willReturnCallback(
                static function () use (&$collisions): void {
                    throw $collisions[] = UniqueTokenIdentifierConstraintViolationException::create();
                },
            );
        $this->captureErrorLogs();

        try {
            $this->sut()->issue($this->accessTokenMock, new DateInterval('PT1H'), self::AUTH_CODE_ID, 3);
        } catch (UniqueTokenIdentifierConstraintViolationException $exception) {
            $this->assertCount(3, $collisions);
            $this->assertSame($collisions[2], $exception);
            $this->assertSame(
                [
                    [
                        'Maximum generation attempts reached.',
                        [
                            'maxGenerationAttempts' => 0,
                            'accessTokenId' => self::ACCESS_TOKEN_ID,
                            'authCodeId' => self::AUTH_CODE_ID,
                        ],
                    ],
                ],
                $this->errorLogs,
            );

            return;
        }

        $this->fail('A refresh token was issued.');
    }


    /**
     * Without a limit of its own the caller gets AbstractTokenIssuer::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS, five.
     */
    public function testAllowsFiveAttemptsByDefault(): void
    {
        $this->randomMock->method('getIdentifier')->willReturn('colliding-id');
        $this->refreshTokenEntityFactoryMock->method('fromData')->willReturn($this->refreshTokenMock);
        $this->refreshTokenRepositoryMock->expects($this->exactly(5))
            ->method('persistNewRefreshToken')
            ->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->sut()->issue($this->accessTokenMock, new DateInterval('PT1H'));
    }


    /**
     * Only a non-positive limit reaches the answer after the loop: at any positive limit the last collision is
     * rethrown from inside it. Then nothing is drawn, built or persisted, the failure is logged and null comes
     * back.
     */
    #[DataProvider('noAttemptProvider')]
    public function testAnswersNullWhenNoAttemptIsAllowed(int $maxGenerationAttempts): void
    {
        $this->randomMock->expects($this->never())->method('getIdentifier');
        $this->refreshTokenEntityFactoryMock->expects($this->never())->method('fromData');
        $this->refreshTokenRepositoryMock->expects($this->never())->method('persistNewRefreshToken');
        $this->captureErrorLogs();

        $this->assertNull(
            $this->sut()->issue($this->accessTokenMock, new DateInterval('PT1H'), null, $maxGenerationAttempts),
        );
        $this->assertSame(
            [
                [
                    'Unable to issue refresh token.',
                    ['accessTokenId' => self::ACCESS_TOKEN_ID, 'authCodeId' => null],
                ],
            ],
            $this->errorLogs,
        );
    }


    public static function noAttemptProvider(): array
    {
        return [
            'zero' => [0],
            'negative' => [-1],
        ];
    }


    /**
     * Only the identifier collision is retried; any other failure of persistence passes through on the first
     * attempt, unlogged.
     */
    public function testLetsAnyOtherPersistenceFailureThrough(): void
    {
        $failure = OAuthServerException::invalidRefreshToken();
        $this->randomMock->expects($this->once())->method('getIdentifier')->willReturn('refresh-token-id');
        $this->refreshTokenEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($this->refreshTokenMock);
        $this->refreshTokenRepositoryMock->expects($this->once())
            ->method('persistNewRefreshToken')
            ->willThrowException($failure);
        $this->loggerMock->expects($this->never())->method('error');

        try {
            $this->sut()->issue($this->accessTokenMock, new DateInterval('PT1H'), null, 3);
        } catch (OAuthServerException $exception) {
            $this->assertSame($failure, $exception);

            return;
        }

        $this->fail('A refresh token was issued.');
    }


    /**
     * League's server error carries its hint at the end of the message and none in getHint().
     */
    private function assertServerError(OidcServerException $exception, string $hint): void
    {
        $this->assertSame('server_error', $exception->getErrorType());
        $this->assertStringEndsWith(': ' . $hint, $exception->getMessage());
        $this->assertNull($exception->getHint());
    }


    private function captureErrorLogs(): void
    {
        $this->loggerMock->method('error')->willReturnCallback(
            function (string|Stringable $message, array $context = []): void {
                $this->errorLogs[] = [(string)$message, $context];
            },
        );
    }
}
