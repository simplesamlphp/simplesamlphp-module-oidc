<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\UserEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * `fromData()` builds a `UserEntity` for a user seen now, stamping both timestamps with the current UTC
 * time; `fromState()` rebuilds one from a database row or from the protocol cache's copy of `getState()`,
 * which `UserRepository::getUserEntityByIdentifier()` hands over unchanged.
 *
 * Unlike the token factories, this one decodes `claims` without `JSON_THROW_ON_ERROR`, so an unparsable
 * column does not raise a `JsonException`: it decodes to `null`, fails the array check, and gets the same
 * "Invalid user entity data" as a wrongly typed column. The flag it does pass, `JSON_INVALID_UTF8_SUBSTITUTE`,
 * is what lets a claim value holding a byte which is not UTF-8 decode at all.
 */
#[CoversClass(UserEntityFactory::class)]
#[UsesClass(Helpers::class)]
#[UsesClass(UserEntity::class)]
class UserEntityFactoryTest extends TestCase
{
    protected const string ID = 'user-id';

    protected const array CLAIMS = ['name' => 'Test User', 'email' => 'test@example.org'];

    protected const string CREATED_AT = '2026-01-01 12:00:00';

    protected const string UPDATED_AT = '2026-01-02 12:00:00';

    /**
     * The two columns read as UTC. They differ by a day so that a swap between them cannot pass, and a row
     * read in server time under a timezone with an offset would give different timestamps for both.
     */
    protected const int CREATED_AT_TIMESTAMP = 1767268800;

    protected const int UPDATED_AT_TIMESTAMP = 1767355200;


    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->helpers = new Helpers();
    }


    protected function sut(): UserEntityFactory
    {
        return new UserEntityFactory($this->helpers);
    }


    /**
     * @return array<string, mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge(
            [
                'id' => self::ID,
                'claims' => '{"name":"Test User","email":"test@example.org"}',
                'updated_at' => self::UPDATED_AT,
                'created_at' => self::CREATED_AT,
            ],
            $overrides,
        );
    }


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
        $this->assertInstanceOf(UserEntityFactory::class, $this->sut());
    }


    public function testFromDataPassesIdentifierAndClaims(): void
    {
        $entity = $this->sut()->fromData(self::ID, self::CLAIMS);

        $this->assertSame(self::ID, $entity->getIdentifier());
        $this->assertSame(self::CLAIMS, $entity->getClaims());
    }


    public function testFromDataDefaultsToNoClaims(): void
    {
        $this->assertSame([], $this->sut()->fromData(self::ID)->getClaims());
    }


    /**
     * A user built from data is new, so created and updated are the same instant, taken once, in UTC.
     */
    public function testFromDataStampsBothTimestampsWithTheSameCurrentUtcTime(): void
    {
        $before = $this->helpers->dateTime()->getUtc()->getTimestamp();
        $entity = $this->sut()->fromData(self::ID);
        $after = $this->helpers->dateTime()->getUtc()->getTimestamp();

        $this->assertSame($entity->getCreatedAt()->getTimestamp(), $entity->getUpdatedAt()->getTimestamp());
        $this->assertGreaterThanOrEqual($before, $entity->getCreatedAt()->getTimestamp());
        $this->assertLessThanOrEqual($after, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame('UTC', $entity->getCreatedAt()->getTimezone()->getName());
        $this->assertSame('UTC', $entity->getUpdatedAt()->getTimezone()->getName());
    }


    public function testFromStateBuildsEveryFieldFromARow(): void
    {
        $entity = $this->sut()->fromState($this->row());

        $this->assertSame(self::ID, $entity->getIdentifier());
        $this->assertSame(self::CLAIMS, $entity->getClaims());
        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::UPDATED_AT_TIMESTAMP, $entity->getUpdatedAt()->getTimestamp());
    }


    /**
     * `UserRepository` caches `getState()` and hands the cached copy straight to `fromState()`, so the two
     * have to agree with each other exactly.
     */
    public function testFromStateRebuildsTheEntityFromItsOwnState(): void
    {
        $original = $this->sut()->fromState($this->row());

        $rebuilt = $this->sut()->fromState($original->getState());

        $this->assertSame($original->getState(), $rebuilt->getState());
        $this->assertSame(self::CLAIMS, $rebuilt->getClaims());
    }


    /**
     * The test container runs on UTC, where reading the columns in server time and reading them as UTC
     * give the same instants, so the plain row test cannot tell the two apart. This one can: on
     * Pacific/Chatham the readings differ by the offset.
     */
    public function testFromStateReadsTimestampsAsUtcWhateverTheServerTimezone(): void
    {
        $previous = date_default_timezone_get();
        date_default_timezone_set('Pacific/Chatham');

        try {
            $entity = $this->sut()->fromState($this->row());
        } finally {
            date_default_timezone_set($previous);
        }

        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::UPDATED_AT_TIMESTAMP, $entity->getUpdatedAt()->getTimestamp());
        $this->assertSame('UTC', $entity->getCreatedAt()->getTimezone()->getName());
        $this->assertSame('UTC', $entity->getUpdatedAt()->getTimezone()->getName());
    }


    /**
     * @return array<string, array{mixed}>
     */
    public static function claimsDecodingToAnEmptyArrayProvider(): array
    {
        return [
            'empty list' => ['[]'],
            'empty object' => ['{}'],
        ];
    }


    #[DataProvider('claimsDecodingToAnEmptyArrayProvider')]
    public function testFromStateDecodesEmptyClaims(string $claims): void
    {
        $this->assertSame([], $this->sut()->fromState($this->row(['claims' => $claims]))->getClaims());
    }


    /**
     * The one thing `JSON_INVALID_UTF8_SUBSTITUTE` buys: a claim value carrying a byte which is not UTF-8
     * still decodes, with the byte replaced by U+FFFD, where the default would refuse the whole column.
     */
    public function testFromStateSubstitutesInvalidUtf8InClaims(): void
    {
        $entity = $this->sut()->fromState($this->row(['claims' => '{"name":"a' . "\xB1" . 'b"}']));

        $this->assertSame(['name' => "a\u{FFFD}b"], $entity->getClaims());
    }


    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidStateProvider(): array
    {
        return [
            'id not a string' => [['id' => 123]],
            'claims not a string' => [['claims' => ['name' => 'Test User']]],
            'claims NULL' => [['claims' => null]],
            'updated_at not a string' => [['updated_at' => 1767355200]],
            'created_at not a string' => [['created_at' => 1767268800]],
            'claims decode to a string' => [['claims' => '"Test User"']],
            'claims decode to a number' => [['claims' => '5']],
            'claims decode to null' => [['claims' => 'null']],
            'claims are not JSON' => [['claims' => '{"name":']],
            'claims are empty' => [['claims' => '']],
        ];
    }


    /**
     * Every rejection, type guard and claims check alike, carries the same detail; the last five rows are
     * the claims check, and the last two of those are the unparsable column that never throws.
     */
    #[DataProvider('invalidStateProvider')]
    public function testFromStateRejectsAnInvalidField(array $overrides): void
    {
        $this->assertServerError(
            'Invalid user entity data',
            fn() => $this->sut()->fromState($this->row($overrides)),
        );
    }
}
