<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryPosition;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;

#[CoversClass(StatusListEntryPosition::class)]
class StatusListEntryPositionTest extends TestCase
{
    protected function record(?DateTimeImmutable $issuedAt): StatusListEntryRecord
    {
        return new StatusListEntryRecord(
            'a-status-list-id',
            42,
            true,
            0,
            null,
            'urn:vc:1',
            'a-hash',
            'employee_card',
            null,
            $issuedAt,
            null,
            str_repeat('a', 64),
        );
    }


    public function testTakesTheKeyOfAnIssuedCredential(): void
    {
        $issuedAt = new DateTimeImmutable('2026-11-11 10:00:00', new DateTimeZone('UTC'));

        $position = StatusListEntryPosition::fromRecord($this->record($issuedAt));

        $this->assertSame($issuedAt, $position->getIssuedAt());
        $this->assertSame('a-status-list-id', $position->getStatusListId());
        $this->assertSame(42, $position->getIdx());
    }


    /**
     * An entry with no issuance moment holds no issued credential, so it has no place in a listing to start
     * after.
     */
    public function testRefusesAnEntryWithoutAnIssuanceMoment(): void
    {
        $this->expectException(StatusListException::class);

        StatusListEntryPosition::fromRecord($this->record(null));
    }
}
