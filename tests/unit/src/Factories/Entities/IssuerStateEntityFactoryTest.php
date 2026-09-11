<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Factories\Entities\IssuerStateEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Exceptions\OpenIdException;

/**
 * Three ways in. `buildNew()` mints an issuer state for a credential offer, filling in whatever the caller
 * left out: a fresh value, a `created_at` of now, and an `expires_at` of `created_at` plus the configured
 * issuer state lifetime. `fromData()` takes every field and enforces the 64-character limit on the value,
 * which is the column width. `fromState()` rebuilds an entity from a database row or from the protocol
 * cache's copy of `getState()`, with the same limit and one fail-safe: a row with no usable `is_revoked`
 * is treated as revoked.
 *
 * The entity spells its expiry getter `getExpirestAt()`; the calls below follow the entity.
 */
#[CoversClass(IssuerStateEntityFactory::class)]
#[UsesClass(Helpers::class)]
#[UsesClass(IssuerStateEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class IssuerStateEntityFactoryTest extends TestCase
{
    protected const string VALUE = 'issuer-state-value';

    protected const string CREATED_AT = '2026-01-01 12:00:00';

    protected const string EXPIRES_AT = '2026-01-02 12:00:00';

    /**
     * The two columns read as UTC. They differ by a day so that a swap between them cannot pass, and a row
     * read in server time under a timezone with an offset would give different timestamps for both.
     */
    protected const int CREATED_AT_TIMESTAMP = 1767268800;

    protected const int EXPIRES_AT_TIMESTAMP = 1767355200;

    protected const string LIFETIME = 'PT5M';


    protected MockObject $moduleConfigMock;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciIssuerStateDuration')->willReturn(new DateInterval(self::LIFETIME));

        $this->helpers = new Helpers();
    }


    protected function sut(): IssuerStateEntityFactory
    {
        return new IssuerStateEntityFactory($this->moduleConfigMock, $this->helpers);
    }


    protected function utc(string $time): DateTimeImmutable
    {
        return new DateTimeImmutable($time, new DateTimeZone('UTC'));
    }


    /**
     * @return array<string, mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge(
            [
                'value' => self::VALUE,
                'created_at' => self::CREATED_AT,
                'expires_at' => self::EXPIRES_AT,
                'is_revoked' => '0',
            ],
            $overrides,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(IssuerStateEntityFactory::class, $this->sut());
    }


    /**
     * The generated value is the SHA-256 hex digest of a random identifier: exactly 64 characters, which
     * is the column width and the most `fromData()` accepts, and different every time.
     */
    public function testBuildNewMintsAFreshValueOfTheMaximumLength(): void
    {
        $sut = $this->sut();

        $first = $sut->buildNew();
        $second = $sut->buildNew();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $first->getValue());
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $second->getValue());
        $this->assertNotSame($first->getValue(), $second->getValue());
    }


    public function testBuildNewStampsNowAndTheConfiguredLifetime(): void
    {
        $before = $this->helpers->dateTime()->getUtc()->getTimestamp();
        $entity = $this->sut()->buildNew();
        $after = $this->helpers->dateTime()->getUtc()->getTimestamp();

        $this->assertGreaterThanOrEqual($before, $entity->getCreatedAt()->getTimestamp());
        $this->assertLessThanOrEqual($after, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame('UTC', $entity->getCreatedAt()->getTimezone()->getName());
        $this->assertSame(
            $entity->getCreatedAt()->add(new DateInterval(self::LIFETIME))->getTimestamp(),
            $entity->getExpirestAt()->getTimestamp(),
        );
        $this->assertFalse($entity->isRevoked());
    }


    /**
     * The lifetime is added to the `created_at` the caller supplied, not to now.
     */
    public function testBuildNewDerivesExpiryFromTheGivenCreatedAt(): void
    {
        $entity = $this->sut()->buildNew(createdAt: $this->utc(self::CREATED_AT));

        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::CREATED_AT_TIMESTAMP + 300, $entity->getExpirestAt()->getTimestamp());
    }


    /**
     * With every field supplied nothing is generated and the configured lifetime is not consulted.
     */
    public function testBuildNewPassesEveryGivenFieldThrough(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerStateDuration');

        $entity = $this->sut()->buildNew(
            self::VALUE,
            $this->utc(self::CREATED_AT),
            $this->utc(self::EXPIRES_AT),
            true,
        );

        $this->assertSame(self::VALUE, $entity->getValue());
        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpirestAt()->getTimestamp());
        $this->assertTrue($entity->isRevoked());
    }


    public function testFromDataPassesEveryArgumentToItsSlot(): void
    {
        $entity = $this->sut()->fromData(
            self::VALUE,
            $this->utc(self::CREATED_AT),
            $this->utc(self::EXPIRES_AT),
            true,
        );

        $this->assertSame(self::VALUE, $entity->getValue());
        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpirestAt()->getTimestamp());
        $this->assertTrue($entity->isRevoked());
    }


    public function testFromDataDefaultsToNotRevoked(): void
    {
        $entity = $this->sut()->fromData(self::VALUE, $this->utc(self::CREATED_AT), $this->utc(self::EXPIRES_AT));

        $this->assertFalse($entity->isRevoked());
    }


    public function testFromDataAcceptsAValueOfExactlySixtyFourCharacters(): void
    {
        $value = str_repeat('v', 64);

        $entity = $this->sut()->fromData($value, $this->utc(self::CREATED_AT), $this->utc(self::EXPIRES_AT));

        $this->assertSame($value, $entity->getValue());
    }


    public function testFromDataRejectsAValueLongerThanSixtyFourCharacters(): void
    {
        $this->expectException(OpenIdException::class);
        $this->expectExceptionMessage('Invalid Issuer State Entity value.');

        $this->sut()->fromData(str_repeat('v', 65), $this->utc(self::CREATED_AT), $this->utc(self::EXPIRES_AT));
    }


    public function testFromStateBuildsEveryFieldFromARow(): void
    {
        $entity = $this->sut()->fromState($this->row());

        $this->assertSame(self::VALUE, $entity->getValue());
        $this->assertSame(self::CREATED_AT_TIMESTAMP, $entity->getCreatedAt()->getTimestamp());
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpirestAt()->getTimestamp());
        $this->assertFalse($entity->isRevoked());
    }


    /**
     * `IssuerStateRepository::find()` caches `getState()` and hands the cached copy straight to
     * `fromState()`, so the two have to agree with each other exactly.
     */
    public function testFromStateRebuildsTheEntityFromItsOwnState(): void
    {
        $original = $this->sut()->fromData(
            self::VALUE,
            $this->utc(self::CREATED_AT),
            $this->utc(self::EXPIRES_AT),
            true,
        );

        $rebuilt = $this->sut()->fromState($original->getState());

        $this->assertSame($original->getState(), $rebuilt->getState());
        $this->assertTrue($rebuilt->isRevoked());
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
        $this->assertSame(self::EXPIRES_AT_TIMESTAMP, $entity->getExpirestAt()->getTimestamp());
        $this->assertSame('UTC', $entity->getCreatedAt()->getTimezone()->getName());
        $this->assertSame('UTC', $entity->getExpirestAt()->getTimezone()->getName());
    }


    /**
     * @return array<string, array{array<string, mixed>}>
     */
    public static function invalidStateProvider(): array
    {
        return [
            'value not a string' => [['value' => 123]],
            'value NULL' => [['value' => null]],
            'created_at not a string' => [['created_at' => 1767268800]],
            'expires_at not a string' => [['expires_at' => 1767355200]],
        ];
    }


    #[DataProvider('invalidStateProvider')]
    public function testFromStateRejectsAnInvalidField(array $overrides): void
    {
        $this->expectException(OpenIdException::class);
        $this->expectExceptionMessage('Invalid Issuer State Entity state.');

        $this->sut()->fromState($this->row($overrides));
    }


    public function testFromStateAcceptsAValueOfExactlySixtyFourCharacters(): void
    {
        $value = str_repeat('v', 64);

        $this->assertSame($value, $this->sut()->fromState($this->row(['value' => $value]))->getValue());
    }


    public function testFromStateRejectsAValueLongerThanSixtyFourCharacters(): void
    {
        $this->expectException(OpenIdException::class);
        $this->expectExceptionMessage('Invalid Issuer State Entity value.');

        $this->sut()->fromState($this->row(['value' => str_repeat('v', 65)]));
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


    /**
     * The fail-safe: `is_revoked` is read with `?? true`, so a row without the key, or with `NULL` in it,
     * builds an entity which is already revoked rather than one which is usable.
     */
    public function testFromStateTreatsAMissingIsRevokedAsRevoked(): void
    {
        $row = $this->row();
        unset($row['is_revoked']);

        $this->assertTrue($this->sut()->fromState($row)->isRevoked());
    }


    public function testFromStateTreatsANullIsRevokedAsRevoked(): void
    {
        $this->assertTrue($this->sut()->fromState($this->row(['is_revoked' => null]))->isRevoked());
    }
}
