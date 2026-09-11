<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * `fromRow()` is an eleven column positional wiring, and this class is the only place an entry row
 * becomes a record. Nothing downstream can tell a mis-wired column from a correct one: swap `issued_at`
 * with `updated_at` and the administration screen goes on showing a moment for every credential, just
 * the wrong one. So every column here holds a value no other column holds, and every getter is asserted
 * against its own -- a fixture where neighbours share a value could not see the swap.
 *
 * The column names are taken from the migration which creates the table rather than from `fromRow()`.
 * Copying them out of the code under test is what would make a wrong column name invisible.
 */
#[CoversClass(StatusListEntryRecord::class)]
class StatusListEntryRecordTest extends TestCase
{
    /**
     * Both of these are sha256 hex in production -- the credential ID hash by `hashCredentialId()`, the
     * subject reference by the keyed hasher -- so both are sixty four characters here rather than some
     * shorter stand-in, and they stay distinct from one another.
     */
    protected const string CREDENTIAL_ID_HASH = 'a1b2c3d4e5f6071829394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9';

    protected const string SUBJECT_REF = '9f2b7c1d4e6a8035bc19d7e4f2a60c8b35719ade46f2c80b1d3e5a7942c60f8b';


    /**
     * A row as a driver hands it back, with every column holding a distinct value.
     *
     * No two of the three timestamps share a date or a time of day, so a swap between any pair shows in
     * both halves. `status` is Suspended rather than Invalid so that it differs from `allocated` once
     * both are read back as `'1'` by a driver which returns strings.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge([
            'status_list_id' => '0f3c9a71',
            'idx' => 4217,
            'allocated' => true,
            'status' => StatusTypeEnum::Suspended->value,
            'expires_at' => '2027-01-05 12:19:04',
            'credential_id' => 'urn:uuid:5a0f7e2c-3b1d-4c8e-9f6a-2d4b8c1e7f3a',
            'credential_id_hash' => self::CREDENTIAL_ID_HASH,
            'credential_configuration_id' => 'UniversityDegree',
            'subject_ref' => self::SUBJECT_REF,
            'issued_at' => '2026-02-06 13:20:05',
            'updated_at' => '2026-03-07 14:21:06',
        ], $overrides);
    }


    /**
     * A row with columns taken away rather than blanked out. Every reader takes its column with the null
     * coalescing operator, so an absent column and a null one are the same thing to all of them as the
     * code stands; both are still written out, since it is the pair which would notice a reader learning
     * to tell them apart.
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
     * Timestamps are compared as instants rather than as wall clocks: the moment is converted to UTC
     * before being formatted, so this says when it is and not merely what it reads as.
     */
    protected function utc(?DateTimeImmutable $moment): ?string
    {
        return $moment?->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }


    /**
     * `fromRow()` is the only production path, but the tests of the administration controller construct
     * a record directly, so the argument order is a contract even though production never exercises it.
     */
    public function testCarriesEveryValueItWasConstructedWith(): void
    {
        $expiresAt = new DateTimeImmutable('2027-01-05 12:19:04', new DateTimeZone('UTC'));
        $issuedAt = new DateTimeImmutable('2026-02-06 13:20:05', new DateTimeZone('UTC'));
        $updatedAt = new DateTimeImmutable('2026-03-07 14:21:06', new DateTimeZone('UTC'));

        $record = new StatusListEntryRecord(
            '0f3c9a71',
            4217,
            true,
            StatusTypeEnum::Suspended->value,
            $expiresAt,
            'urn:uuid:5a0f7e2c-3b1d-4c8e-9f6a-2d4b8c1e7f3a',
            self::CREDENTIAL_ID_HASH,
            'UniversityDegree',
            self::SUBJECT_REF,
            $issuedAt,
            $updatedAt,
        );

        $this->assertSame('0f3c9a71', $record->getStatusListId());
        $this->assertSame(4217, $record->getIdx());
        $this->assertTrue($record->isAllocated());
        $this->assertSame(StatusTypeEnum::Suspended->value, $record->getStatus());
        $this->assertSame($expiresAt, $record->getExpiresAt());
        $this->assertSame('urn:uuid:5a0f7e2c-3b1d-4c8e-9f6a-2d4b8c1e7f3a', $record->getCredentialId());
        $this->assertSame(self::CREDENTIAL_ID_HASH, $record->getCredentialIdHash());
        $this->assertSame('UniversityDegree', $record->getCredentialConfigurationId());
        $this->assertSame(self::SUBJECT_REF, $record->getSubjectRef());
        $this->assertSame($issuedAt, $record->getIssuedAt());
        $this->assertSame($updatedAt, $record->getUpdatedAt());
    }


    /**
     * The wiring test proper. Seven of the eleven arguments are nullable: a moment, then four strings,
     * then two more moments. A fixture holding the same value twice within a run could not tell either
     * member of the pair from the other.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsEveryColumnOfARowIntoItsOwnField(): void
    {
        $record = StatusListEntryRecord::fromRow($this->row());

        $this->assertSame('0f3c9a71', $record->getStatusListId());
        $this->assertSame(4217, $record->getIdx());
        $this->assertTrue($record->isAllocated());
        $this->assertSame(StatusTypeEnum::Suspended->value, $record->getStatus());
        $this->assertSame(StatusTypeEnum::Suspended, $record->getStatusType());
        $this->assertSame('2027-01-05 12:19:04', $this->utc($record->getExpiresAt()));
        $this->assertFalse($record->isNonExpiring());
        $this->assertSame('urn:uuid:5a0f7e2c-3b1d-4c8e-9f6a-2d4b8c1e7f3a', $record->getCredentialId());
        $this->assertSame(self::CREDENTIAL_ID_HASH, $record->getCredentialIdHash());
        $this->assertSame('UniversityDegree', $record->getCredentialConfigurationId());
        $this->assertSame(self::SUBJECT_REF, $record->getSubjectRef());
        $this->assertSame('2026-02-06 13:20:05', $this->utc($record->getIssuedAt()));
        $this->assertSame('2026-03-07 14:21:06', $this->utc($record->getUpdatedAt()));
    }


    /**
     * The three drivers this module supports disagree about what a query returns: some hand every column
     * back as a string whatever the column's type. The same row, read that way, has to produce the same
     * record -- otherwise the type of a value would depend on which database a deployment happens to run.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsARowWhoseValuesAreAllStringsAsThatSameRecord(): void
    {
        $record = StatusListEntryRecord::fromRow($this->rowAsStrings());

        $this->assertSame(4217, $record->getIdx());
        $this->assertTrue($record->isAllocated());
        $this->assertSame(StatusTypeEnum::Suspended->value, $record->getStatus());
        $this->assertSame('2027-01-05 12:19:04', $this->utc($record->getExpiresAt()));
        $this->assertSame('2026-02-06 13:20:05', $this->utc($record->getIssuedAt()));
        $this->assertSame('2026-03-07 14:21:06', $this->utc($record->getUpdatedAt()));
    }


    /**
     * Stored timestamps come back without a zone, so the reader supplies one rather than leaving the value
     * to be read in whatever the server's default happens to be. The moment carries that zone out with it.
     *
     * Asserted under a default zone which is not UTC, deliberately. This container runs in UTC, and there
     * the moment would name UTC whether or not a zone had been supplied at all.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsATimestampAsAMomentInUtc(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            date_default_timezone_set('America/Santiago');

            $expiresAt = StatusListEntryRecord::fromRow($this->row())->getExpiresAt();

            $this->assertInstanceOf(DateTimeImmutable::class, $expiresAt);
            $this->assertSame('UTC', $expiresAt->format('e'));
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }


    /**
     * The same thing said where it can actually fail. The expiry is what decides whether a credential's
     * status can still be changed -- `CredentialStatusService` compares it with the current UTC time --
     * so an expiry read in Zagreb without the zone argument would come back an hour early, and a
     * credential would become unactionable an hour before it expired.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testTimestampsDoNotDependOnTheServerTimezone(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            $seen = [];

            // Zones on both sides of UTC, one of them at an offset which is not a whole number of hours.
            foreach (['UTC', 'Europe/Zagreb', 'America/Santiago', 'Asia/Kathmandu'] as $timezone) {
                date_default_timezone_set($timezone);

                $record = StatusListEntryRecord::fromRow($this->row());

                $seen[] = [
                    $this->utc($record->getExpiresAt()),
                    $this->utc($record->getIssuedAt()),
                    $this->utc($record->getUpdatedAt()),
                ];
            }

            $this->assertSame(
                array_fill(0, 4, ['2027-01-05 12:19:04', '2026-02-06 13:20:05', '2026-03-07 14:21:06']),
                $seen,
            );
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testRefusesARowMissingTheStatusListId(): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('Row is missing the required column "status_list_id".');

        StatusListEntryRecord::fromRow($this->rowWithout('status_list_id'));
    }


    /**
     * @return array<string,array{string}>
     */
    public static function requiredIntegerColumnProvider(): array
    {
        return [
            'idx' => ['idx'],
            'status' => ['status'],
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

        StatusListEntryRecord::fromRow($this->rowWithout($column));
    }


    /**
     * @return array<string,array{mixed,string}>
     */
    public static function nonIntegerValueProvider(): array
    {
        return [
            'a float' => [4217.0, 'float'],
            'a decimal string' => ['4217.0', 'string'],
            'a padded numeric string' => [' 4217', 'string'],
            'the empty string' => ['', 'string'],
            'a boolean' => [true, 'bool'],
        ];
    }


    /**
     * An index which is not an integer is refused rather than truncated. A float in particular: an
     * entry read back as `4217.0` stops the row instead of silently naming an index which may not be the
     * one the credential holds.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('nonIntegerValueProvider')]
    public function testRefusesAnIntegerColumnWhichHoldsSomethingElse(mixed $value, string $expectedType): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(sprintf('Row column "idx" is not an integer, %s given.', $expectedType));

        StatusListEntryRecord::fromRow($this->row(['idx' => $value]));
    }


    /**
     * @return array<string,array{int|string,int}>
     */
    public static function integerValueProvider(): array
    {
        return [
            'an integer' => [4217, 4217],
            'a string of digits, as PDO returns one' => ['4217', 4217],
            'zero' => ['0', 0],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('integerValueProvider')]
    public function testReadsAnIntegerColumnInEveryShapeADriverReturnsIt(int|string $stored, int $expected): void
    {
        $this->assertSame($expected, StatusListEntryRecord::fromRow($this->row(['idx' => $stored]))->getIdx());
    }


    /**
     * @return array<string,array{mixed,bool}>
     */
    public static function allocatedValueProvider(): array
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
            'null' => [null, false],
        ];
    }


    /**
     * The reader behind this is the shared one, whose every shape `StatusListRecordTest` walks through;
     * here it is the shapes each driver actually returns for this column, since `isAllocated()` is what
     * `DbStatusUpdater` and `CredentialStatusService` consult before touching an entry at all.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('allocatedValueProvider')]
    public function testReadsAllocatedInEveryShapeADriverReturnsIt(mixed $stored, bool $expected): void
    {
        $this->assertSame(
            $expected,
            StatusListEntryRecord::fromRow($this->row(['allocated' => $stored]))->isAllocated(),
        );
    }


    /**
     * Not reachable through this schema, where the column has been NOT NULL since the table was created.
     * Worth pinning because the reader's default is the safe direction: an entry with nothing to say
     * about its allocation reads as unallocated, and an unallocated entry is one whose status nothing
     * will change.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testARowWithNoAllocatedColumnReadsAsUnallocated(): void
    {
        $this->assertFalse(StatusListEntryRecord::fromRow($this->rowWithout('allocated'))->isAllocated());
    }


    /**
     * @return array<string,array{int,?\SimpleSAML\OpenID\Codebooks\StatusTypeEnum}>
     */
    public static function statusTypeProvider(): array
    {
        return [
            'valid' => [StatusTypeEnum::Valid->value, StatusTypeEnum::Valid],
            'invalid' => [StatusTypeEnum::Invalid->value, StatusTypeEnum::Invalid],
            'suspended' => [StatusTypeEnum::Suspended->value, StatusTypeEnum::Suspended],
            'application specific 3' => [3, null],
            'unregistered 4' => [4, null],
            'application specific 12' => [12, null],
        ];
    }


    /**
     * The status is stored as the raw value and read back as such; naming it is a separate question,
     * answered with null for a value the library does not register. The raw value survives either way,
     * which is what lets a caller compare against zero rather than mistake an unrecognised status for
     * an absent one.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('statusTypeProvider')]
    public function testNamesTheStatusTypeOnlyForARegisteredValue(int $stored, ?StatusTypeEnum $expected): void
    {
        $record = StatusListEntryRecord::fromRow($this->row(['status' => $stored]));

        $this->assertSame($stored, $record->getStatus());
        $this->assertSame($expected, $record->getStatusType());
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function noExpiryProvider(): array
    {
        return [
            'null' => [null],
            'the empty string' => [''],
        ];
    }


    /**
     * A null expiry is meaningful rather than missing: it marks a credential which never expires, and a
     * list holding one can never be retired.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('noExpiryProvider')]
    public function testAnEntryWithoutAnExpiryIsNonExpiring(mixed $stored): void
    {
        $record = StatusListEntryRecord::fromRow($this->row(['expires_at' => $stored]));

        $this->assertNull($record->getExpiresAt());
        $this->assertTrue($record->isNonExpiring());
    }


    /**
     * What `clearExpiredLinkage()` leaves behind once a credential has expired: the index, its status,
     * its expiry and its allocation, with the four linkage columns set to NULL. The record has to read
     * such a row as exactly that, since the index must go on being reported as taken.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsARowWhoseLinkageHasBeenCleared(): void
    {
        $record = StatusListEntryRecord::fromRow($this->row([
            'credential_id' => null,
            'credential_id_hash' => null,
            'credential_configuration_id' => null,
            'subject_ref' => null,
        ]));

        $this->assertTrue($record->isAllocated());
        $this->assertSame(StatusTypeEnum::Suspended->value, $record->getStatus());
        $this->assertSame('2027-01-05 12:19:04', $this->utc($record->getExpiresAt()));
        $this->assertNull($record->getCredentialId());
        $this->assertNull($record->getCredentialIdHash());
        $this->assertNull($record->getCredentialConfigurationId());
        $this->assertNull($record->getSubjectRef());
    }


    /**
     * What seeding writes: only the list and the index, with every other column at its default or NULL.
     * Such a row is most of the table, and is what a lookup by list and index returns for an index which
     * was never handed out.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsARowWhichWasSeededAndNeverAllocated(): void
    {
        $record = StatusListEntryRecord::fromRow([
            'status_list_id' => '0f3c9a71',
            'idx' => 4217,
            'allocated' => false,
            'status' => 0,
            'expires_at' => null,
            'credential_id' => null,
            'credential_id_hash' => null,
            'credential_configuration_id' => null,
            'subject_ref' => null,
            'issued_at' => null,
            'updated_at' => null,
        ]);

        $this->assertFalse($record->isAllocated());
        $this->assertSame(StatusTypeEnum::Valid, $record->getStatusType());
        $this->assertTrue($record->isNonExpiring());
        $this->assertNull($record->getCredentialId());
        $this->assertNull($record->getCredentialIdHash());
        $this->assertNull($record->getCredentialConfigurationId());
        $this->assertNull($record->getSubjectRef());
        $this->assertNull($record->getIssuedAt());
        $this->assertNull($record->getUpdatedAt());
    }


    /**
     * The nullable columns read the same whether they are absent from the row or null in it.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testNullableColumnsWhichAreAbsentReadAsNull(): void
    {
        $record = StatusListEntryRecord::fromRow($this->rowWithout(
            'expires_at',
            'credential_id',
            'credential_id_hash',
            'credential_configuration_id',
            'subject_ref',
            'issued_at',
            'updated_at',
        ));

        $this->assertNull($record->getExpiresAt());
        $this->assertNull($record->getCredentialId());
        $this->assertNull($record->getCredentialIdHash());
        $this->assertNull($record->getCredentialConfigurationId());
        $this->assertNull($record->getSubjectRef());
        $this->assertNull($record->getIssuedAt());
        $this->assertNull($record->getUpdatedAt());
    }


    /**
     * An empty string is read as no moment rather than handed to the date parser, which reads one as the
     * current time. Without that guard a blank `expires_at` would read as a credential expiring this
     * instant, which `CredentialStatusService` would refuse to act on from then on.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testTimestampsWhichAreEmptyStringsReadAsNoMoment(): void
    {
        $record = StatusListEntryRecord::fromRow($this->row([
            'expires_at' => '',
            'issued_at' => '',
            'updated_at' => '',
        ]));

        $this->assertNull($record->getExpiresAt());
        $this->assertNull($record->getIssuedAt());
        $this->assertNull($record->getUpdatedAt());
    }


    /**
     * A timestamp which cannot be parsed is read as no moment rather than raising, so one unreadable
     * column does not make a whole entry unreadable. For the expiry that reading has a consequence: an
     * entry whose expiry cannot be read presents as one which never expires.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testAnUnparseableTimestampReadsAsNoMomentRatherThanRaising(): void
    {
        $record = StatusListEntryRecord::fromRow($this->row(['expires_at' => 'not a timestamp']));

        $this->assertNull($record->getExpiresAt());
        $this->assertTrue($record->isNonExpiring());
        $this->assertSame('0f3c9a71', $record->getStatusListId());
    }
}
