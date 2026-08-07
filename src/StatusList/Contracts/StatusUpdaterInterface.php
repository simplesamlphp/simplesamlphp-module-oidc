<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Contracts;

use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * Changes the status recorded against an already allocated index.
 *
 * Addressed by list ID and index rather than by the URI a credential carries. The URI is what a
 * Relying Party resolves; the list ID is what identifies the row, and mapping one to the other would
 * add a lookup which buys nothing and stops working when a deployment's base URL changes.
 */
interface StatusUpdaterInterface
{
    /**
     * @return bool Whether the status was changed. False means, and only means, that the entry already
     * held the requested status, which is not an error: repeating a revocation is harmless. Either
     * return value therefore says the entry now holds what was asked for.
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException When the list can not
     * represent the status, which the number of bits per entry fixes permanently at list creation.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusConflictException When concurrent changes kept
     * winning, so the entry holds something other than what was asked for.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When the entry does not exist or
     * was never allocated.
     */
    public function setStatus(string $statusListId, int $idx, StatusTypeEnum $status): bool;

    /**
     * Check that a list could hold this status, without changing anything.
     *
     * Exists so that a caller which records what it is about to do can find out first. Whether a list
     * can carry a status is fixed when the list is created and can never become true later, so a
     * request for one it cannot carry is not a change which failed -- it is a change which was never
     * possible, and writing it into an audit trail would leave a permanent record of a transition
     * that could not have happened.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException When the list can not
     * represent the status.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When the list does not exist.
     */
    public function enforceCanRepresent(string $statusListId, StatusTypeEnum $status): void;

    /**
     * The status currently recorded, or null when the entry does not exist or was never allocated.
     *
     * Returns the raw value rather than a Status Type, so that a value which is application specific
     * or not yet registered is reported as it is instead of being flattened into null.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function getStatusValue(string $statusListId, int $idx): ?int;
}
