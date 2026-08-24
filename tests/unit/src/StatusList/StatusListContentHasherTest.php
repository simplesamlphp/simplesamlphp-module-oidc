<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\StatusListContentHasher;

#[CoversClass(StatusListContentHasher::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListContentHasherTest extends TestCase
{
    protected function sut(): StatusListContentHasher
    {
        return new StatusListContentHasher();
    }


    public function testProducesAHashOfFixedWidth(): void
    {
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $this->sut()->hash(1, 64, []));
    }


    /**
     * A list with nothing revoked still has a hash, and it must not be the empty string, which is
     * reserved for "there is no published token".
     */
    public function testAListWithNothingRevokedStillHashesToSomething(): void
    {
        $hash = $this->sut()->hash(1, 64, []);

        $this->assertNotSame('', $hash);
        $this->assertSame($hash, $this->sut()->hash(1, 64, []));
    }


    /**
     * The compare-and-set which publishes a token compares hashes produced in different processes, so
     * the order the entries happened to arrive in must not change the result.
     */
    public function testIsIndependentOfTheOrderTheEntriesArriveIn(): void
    {
        $this->assertSame(
            $this->sut()->hash(2, 64, [3 => 1, 11 => 2, 40 => 1]),
            $this->sut()->hash(2, 64, [40 => 1, 3 => 1, 11 => 2]),
        );
    }


    public function testChangesWhenAStatusChanges(): void
    {
        $this->assertNotSame(
            $this->sut()->hash(2, 64, [3 => 1]),
            $this->sut()->hash(2, 64, [3 => 2]),
        );
    }


    public function testChangesWhenAnEntryIsAdded(): void
    {
        $this->assertNotSame(
            $this->sut()->hash(2, 64, [3 => 1]),
            $this->sut()->hash(2, 64, [3 => 1, 4 => 1]),
        );
    }


    public function testChangesWhenAnEntryMoves(): void
    {
        $this->assertNotSame(
            $this->sut()->hash(2, 64, [3 => 1]),
            $this->sut()->hash(2, 64, [4 => 1]),
        );
    }


    public function testDistinguishesListsOfDifferentShape(): void
    {
        $this->assertNotSame($this->sut()->hash(1, 64, []), $this->sut()->hash(2, 64, []));
        $this->assertNotSame($this->sut()->hash(1, 64, []), $this->sut()->hash(1, 128, []));
    }


    /**
     * The parts are labelled and delimited precisely so that two different lists can not produce the
     * same input by running together. Bits of 1 with a capacity of 12 and bits of 11 with a capacity of
     * 2 are the pair that plain concatenation would collapse.
     */
    public function testDoesNotCollideOnAmbiguouslyConcatenatedParts(): void
    {
        $this->assertNotSame($this->sut()->hash(1, 12, []), $this->sut()->hash(11, 2, []));
    }


    /**
     * Likewise for the entries: index 1 with status 12 and index 11 with status 2 have to differ.
     */
    public function testDoesNotCollideOnAmbiguouslyConcatenatedEntries(): void
    {
        $this->assertNotSame(
            $this->sut()->hash(8, 64, [1 => 12]),
            $this->sut()->hash(8, 64, [11 => 2]),
        );
    }
}
