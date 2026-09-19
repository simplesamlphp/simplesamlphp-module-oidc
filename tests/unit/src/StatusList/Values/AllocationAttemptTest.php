<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\Values\AllocationAttempt;

/**
 * The one fact an allocation attempt carries between its steps: whether it has already waited on a list
 * another request was preparing and come away with nothing.
 *
 * `DbStatusIndexAllocator` starts every attempt with a fresh one, records the wait once it has happened,
 * and reads the fact back in two places to decide between standing down again and taking over. The fact
 * starts false, and once recorded it stays: nothing un-records it.
 */
#[CoversClass(AllocationAttempt::class)]
class AllocationAttemptTest extends TestCase
{
    public function testHasNotWaitedInVainToBeginWith(): void
    {
        $this->assertFalse((new AllocationAttempt())->hasWaitedInVain());
    }


    public function testRemembersHavingWaitedInVain(): void
    {
        $attempt = new AllocationAttempt();

        $attempt->recordWaitedInVain();

        $this->assertTrue($attempt->hasWaitedInVain());

        $attempt->recordWaitedInVain();

        $this->assertTrue($attempt->hasWaitedInVain());
    }
}
