<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

/**
 * State carried through one attempt to allocate an index, across the several steps it can take.
 *
 * It exists to record one thing: whether this request has already waited for a list another request
 * was preparing, and come away empty handed. That single fact decides the difference between the two
 * situations which look identical from the outside.
 *
 * A request which has not waited yet, and finds someone else preparing an earlier list, should stand
 * down and wait: that is the ordinary cold-start race, and waiting is what keeps the pool to one list.
 *
 * A request which has already waited and still found nothing is looking at a list nobody is going to
 * finish, because whoever created it is gone. Standing down again would delete its own list, wait,
 * create another, and repeat until it ran out of attempts -- failing every issuance for as long as the
 * abandoned row still looked recent. So it takes over instead, at a cost of one surplus list.
 */
class AllocationAttempt
{
    protected bool $hasWaitedInVain = false;

    /**
     * Whether this request has already waited on another request's list without one appearing.
     */
    public function hasWaitedInVain(): bool
    {
        return $this->hasWaitedInVain;
    }

    public function recordWaitedInVain(): void
    {
        $this->hasWaitedInVain = true;
    }
}
