<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Codebooks;

use DateTimeImmutable;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;

#[CoversClass(StatusListExpiryLaneEnum::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListExpiryLaneEnumTest extends TestCase
{
    public function testACredentialWithNoExpiryBelongsInTheNonExpiringLane(): void
    {
        $this->assertSame(StatusListExpiryLaneEnum::NonExpiring, StatusListExpiryLaneEnum::forExpiry(null));
    }


    public function testACredentialWithAnExpiryBelongsInTheExpiringLane(): void
    {
        $this->assertSame(
            StatusListExpiryLaneEnum::Expiring,
            StatusListExpiryLaneEnum::forExpiry(new DateTimeImmutable('2027-08-07 12:00:00')),
        );
    }


    /**
     * Only whether there is an expiry decides the lane, not whether it has already passed. A credential
     * issued with an expiry in the past is an odd thing, but its list can still be retired once the
     * retirement grace has elapsed, which is exactly what the expiring lane means.
     */
    public function testAnExpiryAlreadyInThePastStillBelongsInTheExpiringLane(): void
    {
        $this->assertSame(
            StatusListExpiryLaneEnum::Expiring,
            StatusListExpiryLaneEnum::forExpiry(new DateTimeImmutable('2000-01-01 00:00:00')),
        );
    }


    /**
     * The values are persisted on every Status List row, so changing one would orphan every list already
     * created under the old spelling -- it would match no allocation and never be selected again.
     */
    public function testTheStoredValuesAreStable(): void
    {
        $this->assertSame('expiring', StatusListExpiryLaneEnum::Expiring->value);
        $this->assertSame('non_expiring', StatusListExpiryLaneEnum::NonExpiring->value);
    }
}
