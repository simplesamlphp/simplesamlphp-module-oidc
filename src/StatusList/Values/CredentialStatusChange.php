<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * What happened when a credential's status was set.
 *
 * The distinction it carries is between a change and a repeat. Both leave the credential holding what
 * the caller asked for, so both are successes, but only one of them is news: a caller retrying a
 * request it never saw the answer to should be told the credential is revoked, not that it just
 * revoked it a second time.
 */
class CredentialStatusChange
{
    public function __construct(
        protected readonly string $statusListId,
        protected readonly int $idx,
        protected readonly int $previousStatus,
        protected readonly StatusTypeEnum $status,
        protected readonly bool $isChanged,
    ) {
    }

    public function getStatusListId(): string
    {
        return $this->statusListId;
    }

    public function getIdx(): int
    {
        return $this->idx;
    }

    /**
     * The status observed immediately before the change, as a raw value.
     *
     * Not an authoritative before-image: nothing here holds a lock, so another change can land between
     * the observation and the write. It is what this caller saw, which is what an audit trail records.
     */
    public function getPreviousStatus(): int
    {
        return $this->previousStatus;
    }

    public function getStatus(): StatusTypeEnum
    {
        return $this->status;
    }

    /**
     * Whether this call is what put the credential into that status, as opposed to finding it there.
     */
    public function isChanged(): bool
    {
        return $this->isChanged;
    }
}
