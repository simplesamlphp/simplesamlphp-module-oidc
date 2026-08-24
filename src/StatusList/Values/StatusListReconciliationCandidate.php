<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

/**
 * The part of a Status List the reconciler needs in order to check it.
 *
 * Deliberately not the whole row. A list row carries its published token, which at 8 bits per entry and
 * the default capacity runs to a couple of hundred kilobytes, and the reconciler never looks at it --
 * so reading whole rows would move tens of megabytes per batch through a cron job which only needs to
 * recompute a hash and compare it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\Values\StatusListReconciliationCandidateTest
 */
class StatusListReconciliationCandidate
{
    use DatabaseRowValuesTrait;


    public function __construct(
        protected readonly string $id,
        protected readonly int $bits,
        protected readonly int $capacity,
        protected readonly string $signedTokenContentHash,
        protected readonly int $invalidationCounter,
    ) {
    }


    public function getId(): string
    {
        return $this->id;
    }


    public function getBits(): int
    {
        return $this->bits;
    }


    public function getCapacity(): int
    {
        return $this->capacity;
    }


    public function getSignedTokenContentHash(): string
    {
        return $this->signedTokenContentHash;
    }


    public function getInvalidationCounter(): int
    {
        return $this->invalidationCounter;
    }


    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::asString($row, 'id'),
            self::asInt($row, 'bits'),
            self::asInt($row, 'capacity'),
            self::asNullableString($row, 'signed_token_content_hash') ?? '',
            self::asNullableInt($row, 'invalidation_counter') ?? 0,
        );
    }
}
