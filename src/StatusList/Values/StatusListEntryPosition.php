<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;

/**
 * Where an issued credential sits in the order the credentials of an offer are listed in: when it was issued, then
 * its list and index, which break the tie between the credentials of a batch, issued in the same second.
 *
 * A page of a listing starts after the position of the last credential of the page before it, rather than at a
 * count of rows, so that credentials which expire and leave the listing while a caller pages through it do not
 * shift the pages under the caller.
 *
 * @see \SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository::findLinkedToOffer()
 */
class StatusListEntryPosition
{
    public function __construct(
        protected readonly DateTimeImmutable $issuedAt,
        protected readonly string $statusListId,
        protected readonly int $idx,
    ) {
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When the entry holds no issued credential.
     */
    public static function fromRecord(StatusListEntryRecord $record): self
    {
        $issuedAt = $record->getIssuedAt();

        if (!$issuedAt instanceof DateTimeImmutable) {
            throw new StatusListException('A Status List entry without an issuance moment has no position.');
        }

        return new self($issuedAt, $record->getStatusListId(), $record->getIdx());
    }


    public function getIssuedAt(): DateTimeImmutable
    {
        return $this->issuedAt;
    }


    public function getStatusListId(): string
    {
        return $this->statusListId;
    }


    public function getIdx(): int
    {
        return $this->idx;
    }
}
