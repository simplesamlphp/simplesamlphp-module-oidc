<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use DateTimeImmutable;
use DateTimeZone;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface as OAuth2AccessTokenEntityInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionParameter;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\RefreshTokenEntity;
use SimpleSAML\Module\oidc\Factories\Entities\RefreshTokenEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * The smallest of the three token factories. `fromData()` hands its arguments to the `RefreshTokenEntity`
 * constructor; `fromState()` rebuilds an entity from a database row or from the protocol cache's copy of
 * `getState()`, after `RefreshTokenRepository::findById()` has looked the access token up by
 * `access_token_id` and added the entity itself under `access_token`.
 */
#[CoversClass(RefreshTokenEntityFactory::class)]
#[UsesClass(Helpers::class)]
#[UsesClass(RefreshTokenEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenEntityFactoryTest extends TestCase
{
    protected const string ID = 'refresh-token-id';

    protected const string ACCESS_TOKEN_ID = 'access-token-id';

    protected const string AUTH_CODE_ID = 'auth-code-id';

    protected const string EXPIRES_AT = '2026-01-01 12:00:00';

    /**
     * `self::EXPIRES_AT` read as UTC. A row read in server time under a timezone with an offset would give
     * a different timestamp.
     */
    protected const int EXPIRES_AT_TIMESTAMP = 1767268800;


    protected MockObject $accessTokenMock;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->accessTokenMock = $this->createMock(AccessTokenEntityInterface::class);
        $this->accessTokenMock->method('getIdentifier')->willReturn(self::ACCESS_TOKEN_ID);

        $this->helpers = new Helpers();
    }


    protected function sut(): RefreshTokenEntityFactory
    {
        return new RefreshTokenEntityFactory($this->helpers);
    }


    /**
     * One value for every `fromData()` parameter, keyed by parameter name and none of them the default.
     *
     * @return array<string, mixed>
     */
    protected function fromDataArguments(): array
    {
        return [
            'id' => self::ID,
            'expiryDateTime' => new DateTimeImmutable(self::EXPIRES_AT, new DateTimeZone('UTC')),
            'accessTokenEntity' => $this->accessTokenMock,
            'authCodeId' => self::AUTH_CODE_ID,
            'isRevoked' => true,
        ];
    }


    /**
     * The same fixture as a database row, plus the `access_token` entry the repository adds after looking
     * the access token up by `access_token_id`.
     *
     * @return array<string, mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge(
            [
                'id' => self::ID,
                'expires_at' => self::EXPIRES_AT,
                'access_token_id' => self::ACCESS_TOKEN_ID,
                'is_revoked' => '1',
                'auth_code_id' => self::AUTH_CODE_ID,
                'access_token' => $this->accessTokenMock,
            ],
            $overrides,
        );
    }


    protected function assertEntityCarriesTheFixture(RefreshTokenEntity $entity): void
    {
        $this->assertSame(self::ID, $entity->getIdentifier());
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpiryDateTime()->getTimestamp());
        $this->assertSame($this->accessTokenMock, $entity->getAccessToken());
        $this->assertSame(self::AUTH_CODE_ID, $entity->getAuthCodeId());
        $this->assertTrue($entity->isRevoked());
    }


    /**
     * `OidcServerException::serverError()` appends the detail it is given to a fixed League preamble in
     * the message and leaves the hint empty.
     */
    protected function assertServerError(string $detail, callable $call): void
    {
        try {
            $call();
        } catch (OidcServerException $exception) {
            $this->assertSame('server_error', $exception->getErrorType());
            $this->assertStringEndsWith(': ' . $detail, $exception->getMessage());

            return;
        }

        $this->fail(sprintf('Expected a server error ending with "%s".', $detail));
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RefreshTokenEntityFactory::class, $this->sut());
    }


    public function testFromDataPassesEveryArgumentToItsSlot(): void
    {
        $this->assertEntityCarriesTheFixture($this->sut()->fromData(...$this->fromDataArguments()));
    }


    /**
     * The fixture is spread by name, so this is what makes it a claim about the whole signature: the keys
     * must be the parameter names in declaration order, and no optional parameter may be exercised with
     * its default.
     */
    public function testFromDataFixtureExercisesEveryParameterWithANonDefaultValue(): void
    {
        $arguments = $this->fromDataArguments();
        $parameters = (new ReflectionMethod(RefreshTokenEntityFactory::class, 'fromData'))->getParameters();

        $this->assertSame(
            array_map(fn(ReflectionParameter $parameter): string => $parameter->getName(), $parameters),
            array_keys($arguments),
        );

        foreach ($parameters as $parameter) {
            if (!$parameter->isDefaultValueAvailable()) {
                continue;
            }

            $this->assertNotSame(
                $parameter->getDefaultValue(),
                $arguments[$parameter->getName()],
                sprintf('The fixture value for "%s" must differ from the default.', $parameter->getName()),
            );
        }
    }


    public function testFromDataDefaultsEveryOptionalArgument(): void
    {
        $arguments = $this->fromDataArguments();

        $entity = $this->sut()->fromData(
            $arguments['id'],
            $arguments['expiryDateTime'],
            $arguments['accessTokenEntity'],
        );

        $this->assertNull($entity->getAuthCodeId());
        $this->assertFalse($entity->isRevoked());
    }


    public function testFromStateBuildsEveryFieldFromARow(): void
    {
        $this->assertEntityCarriesTheFixture($this->sut()->fromState($this->row()));
    }


    /**
     * `RefreshTokenRepository::findById()` stores `getState()` in the protocol cache and feeds it back to
     * `fromState()` on the next hit, with only `access_token` added. With every field set, a `getState()`
     * key that `fromState()` does not read comes back as `null` and the states differ.
     */
    public function testFromStateRebuildsTheEntityFromItsOwnState(): void
    {
        $original = $this->sut()->fromData(...$this->fromDataArguments());

        $rebuilt = $this->sut()->fromState($original->getState() + ['access_token' => $this->accessTokenMock]);

        $this->assertSame($original->getState(), $rebuilt->getState());
        $this->assertEntityCarriesTheFixture($rebuilt);
    }


    /**
     * The test container runs on UTC, where reading `expires_at` in server time and reading it as UTC give
     * the same instant, so the timestamp assertion in the plain row test cannot tell them apart. This one
     * can: on Pacific/Chatham the two readings differ by the offset.
     */
    public function testFromStateReadsExpiresAtAsUtcWhateverTheServerTimezone(): void
    {
        $previous = date_default_timezone_get();
        date_default_timezone_set('Pacific/Chatham');

        try {
            $entity = $this->sut()->fromState($this->row());
        } finally {
            date_default_timezone_set($previous);
        }

        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpiryDateTime()->getTimestamp());
        $this->assertSame('UTC', $entity->getExpiryDateTime()->getTimezone()->getName());
    }


    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidStateProvider(): array
    {
        return [
            'id not a string' => [['id' => 123]],
            'expires_at not a string' => [['expires_at' => 1767268800]],
            'access_token missing, as for an unknown access_token_id' => [['access_token' => null]],
            'access_token is a string' => [['access_token' => 'access-token-id']],
        ];
    }


    #[DataProvider('invalidStateProvider')]
    public function testFromStateRejectsAnInvalidField(array $overrides): void
    {
        $this->assertServerError(
            'Invalid Refresh Token state',
            fn() => $this->sut()->fromState($this->row($overrides)),
        );
    }


    /**
     * The guard asks for the module's `AccessTokenEntityInterface`, so an object satisfying only the
     * League one is refused the same way as no access token at all.
     */
    public function testFromStateRejectsAnAccessTokenWhichIsOnlyALeagueAccessToken(): void
    {
        $this->assertServerError(
            'Invalid Refresh Token state',
            fn() => $this->sut()->fromState(
                $this->row(['access_token' => $this->createMock(OAuth2AccessTokenEntityInterface::class)]),
            ),
        );
    }


    /**
     * @return array<string, array{mixed}>
     */
    public static function emptyAuthCodeIdProvider(): array
    {
        return [
            'NULL' => [null],
            'empty' => [''],
            'the string 0' => ['0'],
        ];
    }


    /**
     * `auth_code_id` is normalised with `empty()`, so the string `'0'` is dropped along with `NULL` and the
     * empty string. Current behaviour, pinned so that changing it is a deliberate act.
     */
    #[DataProvider('emptyAuthCodeIdProvider')]
    public function testFromStateTurnsAnEmptyAuthCodeIdIntoNull(mixed $value): void
    {
        $this->assertNull($this->sut()->fromState($this->row(['auth_code_id' => $value]))->getAuthCodeId());
    }


    /**
     * The cast to string is load-bearing: `fromData()` types `authCodeId` as `?string`, so an integer in
     * the row would otherwise be a `TypeError`.
     */
    public function testFromStateCastsANonEmptyAuthCodeIdToString(): void
    {
        $this->assertSame('123', $this->sut()->fromState($this->row(['auth_code_id' => 123]))->getAuthCodeId());
    }


    /**
     * `auth_code_id` is read with `empty()`, which does not mind a key which is not there, so a cached
     * state without it still builds. The other columns are read directly and are not part of this.
     */
    public function testFromStateTreatsAMissingAuthCodeIdAsNull(): void
    {
        $row = $this->row();
        unset($row['auth_code_id']);

        $this->assertNull($this->sut()->fromState($row)->getAuthCodeId());
    }


    /**
     * @return array<string, array{mixed, bool}>
     */
    public static function isRevokedProvider(): array
    {
        return [
            'string 0' => ['0', false],
            'string 1' => ['1', true],
            'int 0' => [0, false],
            'int 1' => [1, true],
            'false' => [false, false],
            'true' => [true, true],
        ];
    }


    /**
     * `is_revoked` is a BOOLEAN column. Which PHP type it comes back as depends on the driver, and the
     * protocol cache hands back the `bool` from `getState()`, so every rendering a `(bool)` cast can take
     * is pinned.
     */
    #[DataProvider('isRevokedProvider')]
    public function testFromStateReadsIsRevokedAsTheDriversRenderIt(mixed $value, bool $expected): void
    {
        $this->assertSame($expected, $this->sut()->fromState($this->row(['is_revoked' => $value]))->isRevoked());
    }
}
