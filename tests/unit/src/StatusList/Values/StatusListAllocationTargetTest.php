<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListAllocationTarget;

/**
 * One combination of pool, policy fingerprint and expiry lane the configuration allocates into.
 *
 * `StatusListLifecycle` builds one per combination and the repository binds all three of each as query
 * parameters when it deactivates the lists which match none of them, so all three are pinned, the lane in
 * both of its values: it is the one member which is not a property of the pool, and the value the
 * repository binds is the enum's.
 */
#[CoversClass(StatusListAllocationTarget::class)]
class StatusListAllocationTargetTest extends TestCase
{
    protected const string POOL_ID = 'employee-badges';

    protected const string POLICY_FINGERPRINT = 'a1b2c3d4e5f6071829394a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5c6d7e8f9';


    #[DataProvider('expiryLaneProvider')]
    public function testCarriesWhatItWasGiven(StatusListExpiryLaneEnum $expiryLane): void
    {
        $target = new StatusListAllocationTarget(self::POOL_ID, self::POLICY_FINGERPRINT, $expiryLane);

        $this->assertSame(self::POOL_ID, $target->getPoolId());
        $this->assertSame(self::POLICY_FINGERPRINT, $target->getPolicyFingerprint());
        $this->assertSame($expiryLane, $target->getExpiryLane());
    }


    /**
     * @return array<string,array{\SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum}>
     */
    public static function expiryLaneProvider(): array
    {
        return [
            'expiring' => [StatusListExpiryLaneEnum::Expiring],
            'non-expiring' => [StatusListExpiryLaneEnum::NonExpiring],
        ];
    }
}
