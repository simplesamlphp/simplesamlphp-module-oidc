<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListReconciliationCandidate;

/**
 * The five columns the reconciler reads of a published Status List, and nothing else of the row.
 *
 * `fromRow()` is the only production path -- the repository's `findPublished()` builds one per row of its
 * five-column query -- and the reconciler uses every field: the bits and capacity to recompute the content
 * hash, the stored hash to compare it with, the ID to find the entries and name the list, and the
 * invalidation counter as the condition on which a stale token is cleared. Three of the five are integers,
 * so every column here holds a value no other column holds, as in `StatusListRecordTest`: a fixture where
 * bits and capacity shared a value could not see them swapped.
 *
 * The column names are taken from the query and the migrations rather than from `fromRow()`, for the
 * reason that test gives.
 */
#[CoversClass(StatusListReconciliationCandidate::class)]
class StatusListReconciliationCandidateTest extends TestCase
{
    protected const string CONTENT_HASH = '9f2b7c1d4e6a8035bc19d7e4f2a60c8b35719ade46f2c80b1d3e5a7942c60f8b';


    /**
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected static function row(array $overrides = []): array
    {
        return array_merge([
            'id' => '0f3c9a71',
            'bits' => 2,
            'capacity' => 4096,
            'signed_token_content_hash' => self::CONTENT_HASH,
            'invalidation_counter' => 9,
        ], $overrides);
    }


    /**
     * @return array<string,mixed>
     */
    protected static function rowWithout(string ...$columns): array
    {
        $row = self::row();

        foreach ($columns as $column) {
            unset($row[$column]);
        }

        return $row;
    }


    /**
     * The tests of the reconciler construct candidates directly, so the argument order is a contract
     * there even though production never exercises it.
     */
    public function testCarriesEveryValueItWasConstructedWith(): void
    {
        $candidate = new StatusListReconciliationCandidate('0f3c9a71', 2, 4096, self::CONTENT_HASH, 9);

        $this->assertSame('0f3c9a71', $candidate->getId());
        $this->assertSame(2, $candidate->getBits());
        $this->assertSame(4096, $candidate->getCapacity());
        $this->assertSame(self::CONTENT_HASH, $candidate->getSignedTokenContentHash());
        $this->assertSame(9, $candidate->getInvalidationCounter());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsEveryColumnOfARowIntoItsOwnField(): void
    {
        $candidate = StatusListReconciliationCandidate::fromRow(self::row());

        $this->assertSame('0f3c9a71', $candidate->getId());
        $this->assertSame(2, $candidate->getBits());
        $this->assertSame(4096, $candidate->getCapacity());
        $this->assertSame(self::CONTENT_HASH, $candidate->getSignedTokenContentHash());
        $this->assertSame(9, $candidate->getInvalidationCounter());
    }


    /**
     * Some drivers hand every column back as a string; the same row read that way is the same candidate.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testReadsARowWhoseValuesAreAllStringsAsThatSameCandidate(): void
    {
        $candidate = StatusListReconciliationCandidate::fromRow(
            self::row(['bits' => '2', 'capacity' => '4096', 'invalidation_counter' => '9']),
        );

        $this->assertSame('0f3c9a71', $candidate->getId());
        $this->assertSame(2, $candidate->getBits());
        $this->assertSame(4096, $candidate->getCapacity());
        $this->assertSame(self::CONTENT_HASH, $candidate->getSignedTokenContentHash());
        $this->assertSame(9, $candidate->getInvalidationCounter());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function testRefusesARowWithoutAnId(): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('Row is missing the required column "id".');

        StatusListReconciliationCandidate::fromRow(self::rowWithout('id'));
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('requiredIntegerColumnProvider')]
    public function testRefusesARowMissingARequiredIntegerColumn(string $column): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(sprintf('Row column "%s" is not an integer, null given.', $column));

        StatusListReconciliationCandidate::fromRow(self::rowWithout($column));
    }


    /**
     * @return array<string,array{string}>
     */
    public static function requiredIntegerColumnProvider(): array
    {
        return [
            'bits' => ['bits'],
            'capacity' => ['capacity'],
        ];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('nonIntegerValueProvider')]
    public function testRefusesAnIntegerColumnWhichHoldsSomethingElse(mixed $value, string $expectedType): void
    {
        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage(
            sprintf('Row column "capacity" is not an integer, %s given.', $expectedType),
        );

        StatusListReconciliationCandidate::fromRow(self::row(['capacity' => $value]));
    }


    /**
     * @return array<string,array{mixed,string}>
     */
    public static function nonIntegerValueProvider(): array
    {
        return [
            'a decimal string' => ['4096.0', 'string'],
            'a float' => [4096.0, 'float'],
        ];
    }


    /**
     * The repository's query keeps rows without a content hash out of the result set, so no candidate
     * arrives this way through it; the reader's own default for the column is what is pinned.
     *
     * @param array<string,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('absentContentHashProvider')]
    public function testAnAbsentContentHashReadsAsAnEmptyOne(array $row): void
    {
        $this->assertSame('', StatusListReconciliationCandidate::fromRow($row)->getSignedTokenContentHash());
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function absentContentHashProvider(): array
    {
        return [
            'no column' => [self::rowWithout('signed_token_content_hash')],
            'a null column' => [self::row(['signed_token_content_hash' => null])],
        ];
    }


    /**
     * The counter column was added by a later migration with a default of zero, so a row read before it
     * ran, or one whose counter is unreadable, is a list which has never been invalidated.
     *
     * @param array<string,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    #[DataProvider('absentInvalidationCounterProvider')]
    public function testAnAbsentInvalidationCounterReadsAsNeverInvalidated(array $row): void
    {
        $this->assertSame(0, StatusListReconciliationCandidate::fromRow($row)->getInvalidationCounter());
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function absentInvalidationCounterProvider(): array
    {
        return [
            'no column' => [self::rowWithout('invalidation_counter')],
            'a null column' => [self::row(['invalidation_counter' => null])],
            'an unreadable column' => [self::row(['invalidation_counter' => 'not a number'])],
        ];
    }
}
