<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;

/**
 * `fromRow()` is a twenty five column positional wiring, and this class is the only place a row becomes
 * a record. Nothing downstream can tell a mis-wired column from a correct one: swap `ttl_seconds` with
 * `token_validity_seconds` and every list goes on publishing tokens, just with the cache lifetime and the
 * validity of the other. So every column here holds a value no other column holds, and every getter is
 * asserted against its own -- a fixture where neighbours share a value could not see the swap.
 *
 * The column names are taken from the migrations which define the table -- the one which creates it,
 * and the two later ones adding `issuer_identifier` and `invalidation_counter` -- rather than from
 * `fromRow()`. Copying them out of the code under test is what would make a wrong column name invisible.
 */
#[CoversClass(StatusListRecord::class)]
class StatusListRecordTest extends TestCase
{
    /**
     * Both of these are sha256 hex in production -- the fingerprint by construction, the content hash
     * by the schema's own account of the column -- so both are sixty four characters here rather than
     * some shorter stand-in, and they stay distinct from one another.
     */
    protected const string POLICY_FINGERPRINT = 'a1b2c3d4e5f6071829394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9';

    protected const string CONTENT_HASH = '9f2b7c1d4e6a8035bc19d7e4f2a60c8b35719ade46f2c80b1d3e5a7942c60f8b';


    /**
     * A row as a driver hands it back, with every column holding a distinct value.
     *
     * Three columns are not named after a getter which reads them, and two of those matter. Both
     * `signed_token_iat`, read by `getSignedTokenIssuedAt()`, and `signed_token_exp`, read by
     * `getSignedTokenExpiresAt()`, are nullable, so a fixture keyed on the getter names would leave the
     * real columns absent and both moments null -- which surfaces only because the assertions below state
     * exact values rather than merely accepting whatever a nullable column happens to hold.
     * `allowed_statuses` differs from both of its getters as well, but is required, so guessing its name
     * wrongly raises instead of passing quietly.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge([
            'id' => '0f3c9a71',
            'uri' => 'https://op.example.org/status-list/0f3c9a71',
            'pool_id' => 'employee-badges',
            'policy_fingerprint' => self::POLICY_FINGERPRINT,
            'expiry_lane' => 'expiring',
            'generation' => 7,
            'bits' => 2,
            'capacity' => 4096,
            'allowed_statuses' => '0,1,2',
            'ttl_seconds' => 300,
            'token_validity_seconds' => 604800,
            'refresh_interval_seconds' => 43200,
            'signing_key_id' => 'key-2026-03',
            'key_profile' => 'did_web',
            'issuer_identifier' => 'did:web:op.example.org',
            'allocated_count' => 1234,
            'is_active' => true,
            'deactivated_at' => '2026-03-01 08:15:00',
            'retired_at' => '2026-04-02 09:16:01',
            'signed_token' => 'header.payload.signature',
            'signed_token_content_hash' => self::CONTENT_HASH,
            'signed_token_iat' => '2026-05-03 10:17:02',
            'signed_token_exp' => '2026-06-04 11:18:03',
            'created_at' => '2026-01-05 12:19:04',
            'invalidation_counter' => 9,
        ], $overrides);
    }


    /**
     * A row with columns taken away rather than blanked out, which is what a row read before the migration
     * adding them has run actually looks like.
     *
     * Every reader takes its column with the null coalescing operator, so an absent column and a null one
     * are the same thing to all of them as the code stands. The two scenarios are still different -- one
     * is a row from an older schema, the other a row from this one -- so both are written out, and it is
     * the pair which would notice a reader learning to tell them apart, as array_key_exists in place of
     * that operator would.
     *
     * @return array<string,mixed>
     */
    protected function rowWithout(string ...$columns): array
    {
        $row = $this->row();

        foreach ($columns as $column) {
            unset($row[$column]);
        }

        return $row;
    }


    /**
     * The same row as every value a string, which is what PDO hands back on the drivers where it does not
     * infer types.
     *
     * @return array<string,string>
     */
    protected function rowAsStrings(): array
    {
        $row = [];

        foreach ($this->row() as $column => $value) {
            if (is_bool($value)) {
                $row[$column] = $value ? '1' : '0';

                continue;
            }

            $row[$column] = is_scalar($value) ? (string)$value : '';
        }

        return $row;
    }


    /**
     * Timestamps are compared as instants rather than as wall clocks, deliberately.
     *
     * The moment is converted to UTC before being formatted, so this says when it is and not merely what
     * it reads as. Formatting it in whatever zone it happens to carry would print the same digits whether
     * or not `asNullableDateTime()` supplied a zone at all, which is what makes the instant the thing
     * worth pinning.
     */
    protected function utc(?DateTimeImmutable $moment): ?string
    {
        return $moment?->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }


    /**
     * Nothing in `src/` constructs a record directly -- `fromRow()` is the only production path -- but the
     * tests of the token provider do, so the argument order is a contract even though production never
     * exercises it. Reordering the constructor and `fromRow()` together would leave every other test here
     * green and break those instead, some distance from the cause.
     */
    public function testCarriesEveryValueItWasConstructedWith(): void
    {
        $record = new StatusListRecord(
            '0f3c9a71',
            'https://op.example.org/status-list/0f3c9a71',
            'employee-badges',
            self::POLICY_FINGERPRINT,
            StatusListExpiryLaneEnum::Expiring,
            7,
            2,
            4096,
            '0,1,2',
            300,
            604800,
            43200,
            'key-2026-03',
            StatusListKeyProfileEnum::DidWeb,
            'did:web:op.example.org',
            1234,
            true,
            new DateTimeImmutable('2026-03-01 08:15:00', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-04-02 09:16:01', new DateTimeZone('UTC')),
            'header.payload.signature',
            self::CONTENT_HASH,
            new DateTimeImmutable('2026-05-03 10:17:02', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-06-04 11:18:03', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-01-05 12:19:04', new DateTimeZone('UTC')),
            9,
        );

        $this->assertSame('0f3c9a71', $record->getId());
        $this->assertSame('https://op.example.org/status-list/0f3c9a71', $record->getUri());
        $this->assertSame('employee-badges', $record->getPoolId());
        $this->assertSame(self::POLICY_FINGERPRINT, $record->getPolicyFingerprint());
        $this->assertSame(StatusListExpiryLaneEnum::Expiring, $record->getExpiryLane());
        $this->assertSame(7, $record->getGeneration());
        $this->assertSame(2, $record->getBits());
        $this->assertSame(4096, $record->getCapacity());
        $this->assertSame('0,1,2', $record->getAllowedStatusesAsString());
        $this->assertSame(300, $record->getTtlSeconds());
        $this->assertSame(604800, $record->getTokenValiditySeconds());
        $this->assertSame(43200, $record->getRefreshIntervalSeconds());
        $this->assertSame('key-2026-03', $record->getSigningKeyId());
        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $record->getKeyProfile());
        $this->assertSame('did:web:op.example.org', $record->getIssuerIdentifier());
        $this->assertSame(1234, $record->getAllocatedCount());
        $this->assertTrue($record->isActive());
        $this->assertSame('2026-03-01 08:15:00', $this->utc($record->getDeactivatedAt()));
        $this->assertSame('2026-04-02 09:16:01', $this->utc($record->getRetiredAt()));
        $this->assertSame('header.payload.signature', $record->getSignedToken());
        $this->assertSame(self::CONTENT_HASH, $record->getSignedTokenContentHash());
        $this->assertSame('2026-05-03 10:17:02', $this->utc($record->getSignedTokenIssuedAt()));
        $this->assertSame('2026-06-04 11:18:03', $this->utc($record->getSignedTokenExpiresAt()));
        $this->assertSame('2026-01-05 12:19:04', $this->utc($record->getCreatedAt()));
        $this->assertSame(9, $record->getInvalidationCounter());
    }


    /**
     * The wiring test. Every column is read, and read into the field named after it rather than into a
     * neighbour of the same type. Eight of the twenty five arguments are integers, six of them in two runs
     * of three -- generation, bits and capacity, then the three second counts -- and the five timestamps
     * fall into a run of two and a run of three. A fixture holding the same number, or the same moment,
     * twice could not tell either member of such a pair from the other.
     */
    public function testReadsEveryColumnOfARowIntoItsOwnField(): void
    {
        $record = StatusListRecord::fromRow($this->row());

        $this->assertSame('0f3c9a71', $record->getId());
        $this->assertSame('https://op.example.org/status-list/0f3c9a71', $record->getUri());
        $this->assertSame('employee-badges', $record->getPoolId());
        $this->assertSame(self::POLICY_FINGERPRINT, $record->getPolicyFingerprint());
        $this->assertSame(StatusListExpiryLaneEnum::Expiring, $record->getExpiryLane());
        $this->assertSame(7, $record->getGeneration());
        $this->assertSame(2, $record->getBits());
        $this->assertSame(4096, $record->getCapacity());
        $this->assertSame('0,1,2', $record->getAllowedStatusesAsString());
        $this->assertSame([0, 1, 2], $record->getAllowedStatusValues());
        $this->assertSame(300, $record->getTtlSeconds());
        $this->assertSame(604800, $record->getTokenValiditySeconds());
        $this->assertSame(43200, $record->getRefreshIntervalSeconds());
        $this->assertSame('key-2026-03', $record->getSigningKeyId());
        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $record->getKeyProfile());
        $this->assertSame('did:web:op.example.org', $record->getIssuerIdentifier());
        $this->assertSame(1234, $record->getAllocatedCount());
        $this->assertTrue($record->isActive());
        $this->assertSame('2026-03-01 08:15:00', $this->utc($record->getDeactivatedAt()));
        $this->assertSame('2026-04-02 09:16:01', $this->utc($record->getRetiredAt()));
        $this->assertSame('header.payload.signature', $record->getSignedToken());
        $this->assertSame(self::CONTENT_HASH, $record->getSignedTokenContentHash());
        $this->assertSame('2026-05-03 10:17:02', $this->utc($record->getSignedTokenIssuedAt()));
        $this->assertSame('2026-06-04 11:18:03', $this->utc($record->getSignedTokenExpiresAt()));
        $this->assertSame('2026-01-05 12:19:04', $this->utc($record->getCreatedAt()));
        $this->assertSame(9, $record->getInvalidationCounter());
    }


    /**
     * The three drivers this module supports disagree about what a query returns: some hand every column
     * back as a string whatever the column's type. The same row, read that way, has to produce the same
     * record -- otherwise the type of a value would depend on which database a deployment happens to run.
     */
    public function testReadsARowWhoseValuesAreAllStringsAsThatSameRecord(): void
    {
        $record = StatusListRecord::fromRow($this->rowAsStrings());

        $this->assertSame(7, $record->getGeneration());
        $this->assertSame(2, $record->getBits());
        $this->assertSame(4096, $record->getCapacity());
        $this->assertSame(300, $record->getTtlSeconds());
        $this->assertSame(604800, $record->getTokenValiditySeconds());
        $this->assertSame(43200, $record->getRefreshIntervalSeconds());
        $this->assertSame(1234, $record->getAllocatedCount());
        $this->assertSame(9, $record->getInvalidationCounter());
        $this->assertTrue($record->isActive());
        $this->assertSame(StatusListExpiryLaneEnum::Expiring, $record->getExpiryLane());
        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $record->getKeyProfile());
        $this->assertSame('2026-01-05 12:19:04', $this->utc($record->getCreatedAt()));
    }


    /**
     * Stored timestamps come back without a zone, so the reader supplies one rather than leaving the value
     * to be read in whatever the server's default happens to be. The moment carries that zone out with it.
     *
     * Asserted under a default zone which is not UTC, deliberately. This container runs in UTC, and there
     * the moment would name UTC whether or not a zone had been supplied at all -- so the same assertion
     * made without setting the default would hold no matter what the reader did.
     */
    public function testReadsATimestampAsAMomentInUtc(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            date_default_timezone_set('America/Santiago');

            $createdAt = StatusListRecord::fromRow($this->row())->getCreatedAt();

            $this->assertInstanceOf(DateTimeImmutable::class, $createdAt);
            $this->assertSame('UTC', $createdAt->format('e'));
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }


    /**
     * The same thing said where it can actually fail. Formatting a moment in its own zone prints the same
     * digits whether or not a zone was supplied, so only a server which is not itself in UTC can tell the
     * difference: read in Zagreb without the zone argument, `12:19:04` stored would come back as an
     * instant an hour earlier, and every token's `iat` would be off by the server's offset.
     */
    public function testTimestampsDoNotDependOnTheServerTimezone(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            $seen = [];

            // Zones on both sides of UTC, one of them at an offset which is not a whole number of hours.
            foreach (['UTC', 'Europe/Zagreb', 'America/Santiago', 'Asia/Kathmandu'] as $timezone) {
                date_default_timezone_set($timezone);

                $seen[] = $this->utc(StatusListRecord::fromRow($this->row())->getCreatedAt());
            }

            $this->assertSame(array_fill(0, 4, '2026-01-05 12:19:04'), $seen);
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }


    /**
     * @return array<string,array{string}>
     */
    public static function requiredTextColumnProvider(): array
    {
        return [
            'id' => ['id'],
            'uri' => ['uri'],
            'pool id' => ['pool_id'],
            'policy fingerprint' => ['policy_fingerprint'],
            'expiry lane' => ['expiry_lane'],
            'allowed statuses' => ['allowed_statuses'],
            'signing key id' => ['signing_key_id'],
            'key profile' => ['key_profile'],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('requiredTextColumnProvider')]
    public function testRefusesARowMissingARequiredTextColumn(string $column): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(sprintf('Row is missing the required column "%s".', $column));

        StatusListRecord::fromRow($this->rowWithout($column));
    }


    /**
     * @return array<string,array{string}>
     */
    public static function requiredIntegerColumnProvider(): array
    {
        return [
            'generation' => ['generation'],
            'bits' => ['bits'],
            'capacity' => ['capacity'],
            'ttl seconds' => ['ttl_seconds'],
            'token validity seconds' => ['token_validity_seconds'],
            'refresh interval seconds' => ['refresh_interval_seconds'],
            'allocated count' => ['allocated_count'],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('requiredIntegerColumnProvider')]
    public function testRefusesARowMissingARequiredIntegerColumn(string $column): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(sprintf('Row column "%s" is not an integer, null given.', $column));

        StatusListRecord::fromRow($this->rowWithout($column));
    }


    /**
     * @return array<string,array{mixed,string}>
     */
    public static function nonIntegerValueProvider(): array
    {
        return [
            'a float' => [4096.0, 'float'],
            'a decimal string' => ['4096.0', 'string'],
            'a padded numeric string' => [' 4096', 'string'],
            'a signed numeric string' => ['+4096', 'string'],
            'a hexadecimal string' => ['0x1000', 'string'],
            'the empty string' => ['', 'string'],
            'a boolean' => [true, 'bool'],
        ];
    }


    /**
     * The reader takes an integer, or a string of digits with an optional leading minus, and nothing
     * else. A float in particular is refused rather than truncated, so a column read back as `4096.0`
     * stops the row instead of silently becoming a capacity which was never written.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('nonIntegerValueProvider')]
    public function testRefusesAnIntegerColumnWhichHoldsSomethingElse(mixed $value, string $expectedType): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(
            sprintf('Row column "capacity" is not an integer, %s given.', $expectedType),
        );

        StatusListRecord::fromRow($this->row(['capacity' => $value]));
    }


    /**
     * @return array<string,array{int|string,int}>
     */
    public static function integerValueProvider(): array
    {
        return [
            'an integer' => [7, 7],
            'a string of digits, as PDO returns one' => ['7', 7],
            'zero' => ['0', 0],
            'a negative number' => ['-7', -7],
        ];
    }


    /**
     * A negative generation is nonsense, and is read anyway. Nothing rejects one: the column carries no
     * check of its own -- unlike bits and capacity, which do -- and this reader converts rather than
     * validates. Pinned as the behaviour it is, not endorsed.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('integerValueProvider')]
    public function testReadsAnIntegerColumnInEveryShapeADriverReturnsIt(int|string $stored, int $expected): void
    {
        $this->assertSame($expected, StatusListRecord::fromRow($this->row(['generation' => $stored]))->getGeneration());
    }


    /**
     * @return array<string,array{string,\SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum}>
     */
    public static function expiryLaneProvider(): array
    {
        return [
            'expiring' => ['expiring', StatusListExpiryLaneEnum::Expiring],
            'non expiring' => ['non_expiring', StatusListExpiryLaneEnum::NonExpiring],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('expiryLaneProvider')]
    public function testReadsEachExpiryLane(string $stored, StatusListExpiryLaneEnum $expected): void
    {
        $record = StatusListRecord::fromRow($this->row(['expiry_lane' => $stored]));

        $this->assertSame($expected, $record->getExpiryLane());
    }


    /**
     * An unrecognised lane is refused rather than read as either member. So is an unrecognised key
     * profile, and fifteen columns are required outright -- the two providers above name all fifteen --
     * so the refusal is not what singles this column out. The argument for it is. Reading a wrong lane
     * would let a credential which never expires be allocated into a list of credentials which do, which
     * is the single thing the lane exists to prevent, and that damage is silent and permanent: the list
     * can then never be retired, and nothing ever says why.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testRefusesAnUnknownExpiryLaneRatherThanGuessingOne(): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(
            'Status List row column "expiry_lane" holds an unknown expiry lane "quarterly".',
        );

        StatusListRecord::fromRow($this->row(['expiry_lane' => 'quarterly']));
    }


    /**
     * @return array<string,array{string,\SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum}>
     */
    public static function keyProfileProvider(): array
    {
        return [
            'did:jwk' => ['did_jwk', StatusListKeyProfileEnum::DidJwk],
            'did:web' => ['did_web', StatusListKeyProfileEnum::DidWeb],
            'jwks' => ['jwks', StatusListKeyProfileEnum::Jwks],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('keyProfileProvider')]
    public function testReadsEachKeyProfile(string $stored, StatusListKeyProfileEnum $expected): void
    {
        $record = StatusListRecord::fromRow($this->row(['key_profile' => $stored]));

        $this->assertSame($expected, $record->getKeyProfile());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testRefusesAnUnknownKeyProfileRatherThanGuessingOne(): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(
            'Status List row column "key_profile" holds an unknown key profile "x509".',
        );

        StatusListRecord::fromRow($this->row(['key_profile' => 'x509']));
    }


    /**
     * @return array<string,array{mixed,bool}>
     */
    public static function activeValueProvider(): array
    {
        return [
            'a real boolean true' => [true, true],
            'a real boolean false' => [false, false],
            'PostgreSQL t' => ['t', true],
            'PostgreSQL f' => ['f', false],
            'MySQL 1' => [1, true],
            'MySQL 0' => [0, false],
            'SQLite string 1' => ['1', true],
            'SQLite string 0' => ['0', false],
            'the word true' => ['true', true],
            'the word false' => ['false', false],
            'the word yes' => ['yes', true],
            'the word no' => ['no', false],
            'the letter n' => ['n', false],
            'an uppercase F' => ['F', false],
            'an uppercase FALSE' => ['FALSE', false],
            'the empty string' => ['', false],
            'null' => [null, false],
            'a shape meaning nothing in particular' => ['0.0', true],
        ];
    }


    /**
     * The three drivers return a boolean in at least six shapes between them. Only the values which
     * actually mean false are read as false, so an unrecognised one is read as active rather than quietly
     * taking a list out of the allocation pool -- which is why `0.0` is true here and `0` is not.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('activeValueProvider')]
    public function testReadsIsActiveInEveryShapeADriverReturnsIt(mixed $stored, bool $expected): void
    {
        $this->assertSame($expected, StatusListRecord::fromRow($this->row(['is_active' => $stored]))->isActive());
    }


    /**
     * Not reachable through this schema, where the column has been NOT NULL since the table was created.
     * Worth pinning because the reader's own default is the opposite of the column's: a row with nothing
     * to say about it reads as inactive, where the column would have written it active. Inactive is the
     * safe direction -- such a list is served but allocated into no further.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testARowWithNoIsActiveColumnReadsAsInactive(): void
    {
        $this->assertFalse(StatusListRecord::fromRow($this->rowWithout('is_active'))->isActive());
    }


    /**
     * Added by a later migration than the table, so a row read before that migration has run has no such
     * column -- which reads the same as a list created under a key profile which names the issuer some
     * other way. Both readings are true of the row in question, which is why this one defaults rather than
     * raising the way the lane above does.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAListCreatedBeforeTheIssuerIdentifierColumnExistedNamesNoIssuer(): void
    {
        $this->assertNull(StatusListRecord::fromRow($this->rowWithout('issuer_identifier'))->getIssuerIdentifier());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAListUnderAProfileWhichNamesTheIssuerOtherwiseNamesNoIssuer(): void
    {
        $record = StatusListRecord::fromRow($this->row([
            'key_profile' => 'jwks',
            'issuer_identifier' => null,
        ]));

        $this->assertNull($record->getIssuerIdentifier());
        $this->assertSame(StatusListKeyProfileEnum::Jwks, $record->getKeyProfile());
    }


    /**
     * The hash is never null, so that a compare-and-set can match it. A row written before the column had
     * its default, or by hand, would still read as null, and "nothing published" is the safe reading --
     * the alternative is a signer matching a value which means nothing.
     *
     * The token is present in this row, so the empty hash is doing the work on its own. A test which
     * blanked both could not tell which of the two `hasPublishedToken()` was reading.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAMissingContentHashReadsAsNothingPublished(): void
    {
        $record = StatusListRecord::fromRow($this->rowWithout('signed_token_content_hash'));

        $this->assertSame('', $record->getSignedTokenContentHash());
        $this->assertSame('header.payload.signature', $record->getSignedToken());
        $this->assertFalse($record->hasPublishedToken());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testANullContentHashReadsAsNothingPublished(): void
    {
        $record = StatusListRecord::fromRow($this->row(['signed_token_content_hash' => null]));

        $this->assertSame('', $record->getSignedTokenContentHash());
        $this->assertFalse($record->hasPublishedToken());
    }


    /**
     * Also added by a later migration, and defaulted for the same reason: zero is the value the column
     * itself defaults to, so a row read before the migration behaves exactly as a list which has never
     * been invalidated -- which it has not.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAListCreatedBeforeTheInvalidationCounterColumnExistedHasNeverBeenInvalidated(): void
    {
        $record = StatusListRecord::fromRow($this->rowWithout('invalidation_counter'));

        $this->assertSame(0, $record->getInvalidationCounter());
    }


    /**
     * A present but unreadable counter takes the same default as an absent one, which is a different
     * situation reading the same way. Not reachable through this schema, where the column is an integer
     * with a default, so it is pinned rather than reported.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAnUnreadableInvalidationCounterAlsoReadsAsNeverInvalidated(): void
    {
        $record = StatusListRecord::fromRow($this->row(['invalidation_counter' => 'not a number']));

        $this->assertSame(0, $record->getInvalidationCounter());
    }


    /**
     * Four of these five columns are nullable in the schema. `created_at` is not, and is read through the
     * nullable reader anyway, so it is here for the reading rather than because a row could arrive so.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testTimestampsWhichAreNullReadAsNoMoment(): void
    {
        $record = StatusListRecord::fromRow($this->row([
            'deactivated_at' => null,
            'retired_at' => null,
            'signed_token_iat' => null,
            'signed_token_exp' => null,
            'created_at' => null,
        ]));

        $this->assertNull($record->getDeactivatedAt());
        $this->assertNull($record->getRetiredAt());
        $this->assertNull($record->getSignedTokenIssuedAt());
        $this->assertNull($record->getSignedTokenExpiresAt());
        $this->assertNull($record->getCreatedAt());
    }


    /**
     * An empty string is read as no moment rather than handed to the date parser, which reads one as the
     * current time. Without that guard a blank `retired_at` would make every list report itself retired
     * at this instant, and a blank `signed_token_exp` would expire every published token on the spot.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testTimestampsWhichAreEmptyStringsReadAsNoMoment(): void
    {
        $record = StatusListRecord::fromRow($this->row([
            'deactivated_at' => '',
            'retired_at' => '',
            'signed_token_iat' => '',
            'signed_token_exp' => '',
            'created_at' => '',
        ]));

        $this->assertNull($record->getDeactivatedAt());
        $this->assertNull($record->getRetiredAt());
        $this->assertNull($record->getSignedTokenIssuedAt());
        $this->assertNull($record->getSignedTokenExpiresAt());
        $this->assertNull($record->getCreatedAt());
    }


    /**
     * A timestamp which cannot be parsed is read as no moment rather than raising, so one unreadable
     * column does not make a whole list unreadable.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAnUnparseableTimestampReadsAsNoMomentRatherThanRaising(): void
    {
        $record = StatusListRecord::fromRow($this->row(['created_at' => 'not a timestamp']));

        $this->assertNull($record->getCreatedAt());
        $this->assertSame('0f3c9a71', $record->getId());
    }


    /**
     * `created_at` is NOT NULL in the schema and is read through the nullable reader regardless, so a row
     * without it is accepted rather than refused. Worth pinning because the tolerance is invisible from
     * the outside: every caller of `getCreatedAt()` carries the optionality of a column which cannot in
     * fact be empty.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testARowWithNoCreatedAtIsAcceptedWithNoCreationMoment(): void
    {
        $record = StatusListRecord::fromRow($this->rowWithout('created_at'));

        $this->assertNull($record->getCreatedAt());
        $this->assertSame('0f3c9a71', $record->getId());
    }


    /**
     * The zone is supplied as the default for a value which names none, not as a coercion of one which
     * does, so a timestamp carrying an offset is read as the instant it names rather than shifted to a
     * different one. Not reachable through this schema -- the column is DATETIME on MySQL and a bare
     * TIMESTAMP elsewhere, which PostgreSQL reads as being without a time zone -- so it is pinned rather
     * than reported, against the column type being changed under it.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testATimestampWhichNamesItsOwnZoneIsReadAsTheInstantItNames(): void
    {
        $record = StatusListRecord::fromRow($this->row(['created_at' => '2026-01-05 14:19:04+02:00']));

        $this->assertSame('2026-01-05 12:19:04', $this->utc($record->getCreatedAt()));
    }


    /**
     * @return array<string,array{string,int[]}>
     */
    public static function allowedStatusesProvider(): array
    {
        return [
            'none at all' => ['', []],
            'a single value' => ['1', [1]],
            'the default set' => ['0,1,2', [0, 1, 2]],
            'values in no particular order' => ['2,0', [2, 0]],
            'a value no status type is registered for' => ['0,15', [0, 15]],
            'padding around the separators' => [' 0 , 1 ', [0, 1]],
            'something which is not a number' => ['1,suspended', [1, 0]],
        ];
    }


    /**
     * @param int[] $expected
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('allowedStatusesProvider')]
    public function testReadsTheAllowedStatusesAsValues(string $stored, array $expected): void
    {
        $record = StatusListRecord::fromRow($this->row(['allowed_statuses' => $stored]));

        $this->assertSame($expected, $record->getAllowedStatusValues());
        $this->assertSame($stored, $record->getAllowedStatusesAsString());
    }


    /**
     * The empty column is answered before the split rather than after it, and the difference is the whole
     * point: splitting an empty string yields one empty piece, which becomes the integer zero, and a list
     * which allows nothing would report that it allows the status meaning valid.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAListWhichAllowsNothingAllowsNoStatusAtAll(): void
    {
        $record = StatusListRecord::fromRow($this->row(['allowed_statuses' => '']));

        $this->assertSame([], $record->getAllowedStatusValues());
        $this->assertFalse($record->isStatusValueAllowed(0));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAnswersWhetherAStatusValueIsAllowed(): void
    {
        $record = StatusListRecord::fromRow($this->row(['allowed_statuses' => '0,1']));

        $this->assertTrue($record->isStatusValueAllowed(0));
        $this->assertTrue($record->isStatusValueAllowed(1));
        $this->assertFalse($record->isStatusValueAllowed(2));
        $this->assertFalse($record->isStatusValueAllowed(-1));
    }


    /**
     * Compared as a raw value rather than as a Status Type, so a value which is application specific or
     * not yet registered is answered the same way as a registered one.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAllowsAStatusValueNoStatusTypeIsRegisteredFor(): void
    {
        $record = StatusListRecord::fromRow($this->row(['allowed_statuses' => '0,15']));

        $this->assertTrue($record->isStatusValueAllowed(15));
        $this->assertFalse($record->isStatusValueAllowed(14));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testIsRetiredOnlyOnceARetirementMomentIsRecorded(): void
    {
        $this->assertTrue(StatusListRecord::fromRow($this->row())->isRetired());
        $this->assertFalse(StatusListRecord::fromRow($this->row(['retired_at' => null]))->isRetired());
        $this->assertFalse(StatusListRecord::fromRow($this->rowWithout('retired_at'))->isRetired());
    }


    /**
     * Deactivation and retirement are adjacent nullable timestamps, and they mean different things: a
     * deactivated list is closed to further allocation but still served, a retired one is finished with.
     * Read from the wrong column, every deactivated list would report itself retired.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAListDeactivatedButNotRetiredIsNotRetired(): void
    {
        $record = StatusListRecord::fromRow($this->row(['retired_at' => null]));

        $this->assertSame('2026-03-01 08:15:00', $this->utc($record->getDeactivatedAt()));
        $this->assertFalse($record->isRetired());
    }


    /**
     * @return array<string,array{?string,string,bool}>
     */
    public static function publishedTokenProvider(): array
    {
        return [
            'a token and the hash of what it was signed over' => [
                'header.payload.signature',
                self::CONTENT_HASH,
                true,
            ],
            'a hash but no token' => [null, self::CONTENT_HASH, false],
            'a hash but an empty token' => ['', self::CONTENT_HASH, false],
            'a token but no hash, as an invalidation leaves it' => ['header.payload.signature', '', false],
            'neither' => [null, '', false],
        ];
    }


    /**
     * Both halves have to be there. The hash is what a compare-and-set matches on, so a token without one
     * cannot be shown to still correspond to the list it was signed over, and is not served as it
     * stands.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('publishedTokenProvider')]
    public function testHasAPublishedTokenOnlyWithBothATokenAndItsHash(
        ?string $token,
        string $hash,
        bool $expected,
    ): void {
        $record = StatusListRecord::fromRow($this->row([
            'signed_token' => $token,
            'signed_token_content_hash' => $hash,
        ]));

        $this->assertSame($expected, $record->hasPublishedToken());
        $this->assertSame($token, $record->getSignedToken());
        $this->assertSame($hash, $record->getSignedTokenContentHash());
    }


    /**
     * The counter is the only constructor argument with a default. Being added by a later migration is
     * not what earns it one -- `issuer_identifier` arrived later still and has none -- but that column is
     * nullable, which already lets a caller say nothing about it, where the counter is a plain int and a
     * default is the only way to leave it out. Every other construction in the tests passes all twenty
     * five arguments, so that default was free to change with nothing to say so.
     */
    public function testARecordBuiltWithoutAnInvalidationCounterHasNeverBeenInvalidated(): void
    {
        $record = new StatusListRecord(
            '0f3c9a71',
            'https://op.example.org/status-list/0f3c9a71',
            'employee-badges',
            self::POLICY_FINGERPRINT,
            StatusListExpiryLaneEnum::Expiring,
            7,
            2,
            4096,
            '0,1,2',
            300,
            604800,
            43200,
            'key-2026-03',
            StatusListKeyProfileEnum::Jwks,
            null,
            0,
            true,
            null,
            null,
            null,
            '',
            null,
            null,
            null,
        );

        $this->assertSame(0, $record->getInvalidationCounter());
    }
}
