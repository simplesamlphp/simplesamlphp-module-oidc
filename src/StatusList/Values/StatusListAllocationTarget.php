<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;

/**
 * One combination of pool, policy and lane which the current configuration would allocate into.
 *
 * Allocation selects a list by all three of these together, so all three are what decides whether an
 * existing list is still reachable. A list matching none of the combinations the configuration currently
 * produces will never be allocated into again, and something has to notice that: nothing would ever fill
 * it, so nothing would ever deactivate it, and a list which is never deactivated is never retired.
 *
 * The lane is here for a reason worth stating, because it is the one thing on this list which is not a
 * property of the pool. Removing the last credential lifetime from a pool leaves its policy fingerprint
 * untouched while routing every new credential to the other lane, so without the lane in the comparison
 * the old list would stay active, reachable by nothing, and served for ever.
 *
 * @see \SimpleSAML\Module\oidc\Repositories\StatusListRepository::deactivateSuperseded()
 */
class StatusListAllocationTarget
{
    public function __construct(
        protected readonly string $poolId,
        protected readonly string $policyFingerprint,
        protected readonly StatusListExpiryLaneEnum $expiryLane,
    ) {
    }


    public function getPoolId(): string
    {
        return $this->poolId;
    }


    public function getPolicyFingerprint(): string
    {
        return $this->policyFingerprint;
    }


    public function getExpiryLane(): StatusListExpiryLaneEnum
    {
        return $this->expiryLane;
    }
}
