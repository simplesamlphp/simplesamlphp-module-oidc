<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;

/**
 * One row of the Status List table, as read back from storage.
 *
 * Everything the pool configured is recorded here rather than read from configuration at use time,
 * deliberately. A list has to stay publishable exactly as its holders resolved it, so changing a pool's
 * settings must not change what an existing list emits: new settings route new credentials to new
 * lists, and the old lists keep being served under the policy they were created with.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListRecordTest
 */
class StatusListRecord
{
    use DatabaseRowValuesTrait;

    /**
     * @param string $id Opaque public identifier, being the last path segment of the list's URI.
     * @param string $uri The authoritative URI. Referenced Tokens carry this string and Status List
     * Tokens repeat it as `sub`, both verbatim, so it is never rebuilt from parts.
     * @param \SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum $expiryLane Which kind of
     * credential this list accepts, as regards expiry. Fixed at creation, and part of what allocation
     * filters candidate lists on, so that a list holding credentials which never expire -- and which
     * therefore can never be retired -- never also holds credentials which do.
     * @param string $allowedStatuses Comma separated status values this list may carry.
     * @param string $signedTokenContentHash Hash of the content the published token was signed over.
     * An empty string means there is no valid published token, whether because none was ever produced
     * or because a status change invalidated it. Never null, so that a compare-and-set can match it.
     * @param int $invalidationCounter How many times the published token has been invalidated. The
     * hash alone cannot settle publication, because an invalidation arriving while it is already empty
     * leaves it empty and a signer which observed the empty value would still match. This always
     * changes, so that signer no longer does.
     */
    public function __construct(
        protected readonly string $id,
        protected readonly string $uri,
        protected readonly string $poolId,
        protected readonly string $policyFingerprint,
        protected readonly StatusListExpiryLaneEnum $expiryLane,
        protected readonly int $generation,
        protected readonly int $bits,
        protected readonly int $capacity,
        protected readonly string $allowedStatuses,
        protected readonly int $ttlSeconds,
        protected readonly int $tokenValiditySeconds,
        protected readonly int $refreshIntervalSeconds,
        protected readonly string $signingKeyId,
        protected readonly StatusListKeyProfileEnum $keyProfile,
        protected readonly int $allocatedCount,
        protected readonly bool $isActive,
        protected readonly ?DateTimeImmutable $deactivatedAt,
        protected readonly ?DateTimeImmutable $retiredAt,
        protected readonly ?string $signedToken,
        protected readonly string $signedTokenContentHash,
        protected readonly ?DateTimeImmutable $signedTokenIssuedAt,
        protected readonly ?DateTimeImmutable $signedTokenExpiresAt,
        protected readonly ?DateTimeImmutable $createdAt,
        protected readonly int $invalidationCounter = 0,
    ) {
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getUri(): string
    {
        return $this->uri;
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

    /**
     * Generation within this list's pool, policy and lane, which is the scope its uniqueness is
     * declared over and the only scope anything compares it in. Generations of one lane are therefore
     * not contiguous with another's, and nothing depends on their being so.
     */
    public function getGeneration(): int
    {
        return $this->generation;
    }

    public function getBits(): int
    {
        return $this->bits;
    }

    public function getCapacity(): int
    {
        return $this->capacity;
    }

    /**
     * @return int[]
     */
    public function getAllowedStatusValues(): array
    {
        if ($this->allowedStatuses === '') {
            return [];
        }

        return array_map('intval', explode(',', $this->allowedStatuses));
    }

    /**
     * Whether this list may carry the given status.
     *
     * Compared as a raw value rather than as a Status Type, so that a value which is application
     * specific or not yet registered is answered the same way as a registered one.
     */
    public function isStatusValueAllowed(int $status): bool
    {
        return in_array($status, $this->getAllowedStatusValues(), true);
    }

    public function getAllowedStatusesAsString(): string
    {
        return $this->allowedStatuses;
    }

    public function getTtlSeconds(): int
    {
        return $this->ttlSeconds;
    }

    public function getTokenValiditySeconds(): int
    {
        return $this->tokenValiditySeconds;
    }

    public function getRefreshIntervalSeconds(): int
    {
        return $this->refreshIntervalSeconds;
    }

    public function getSigningKeyId(): string
    {
        return $this->signingKeyId;
    }

    public function getKeyProfile(): StatusListKeyProfileEnum
    {
        return $this->keyProfile;
    }

    /**
     * Advisory count of allocated entries. Incrementing it is a separate statement from the allocation
     * itself, so it can undercount; it drives the decision to rotate, never a correctness decision.
     */
    public function getAllocatedCount(): int
    {
        return $this->allocatedCount;
    }

    public function isActive(): bool
    {
        return $this->isActive;
    }

    public function getDeactivatedAt(): ?DateTimeImmutable
    {
        return $this->deactivatedAt;
    }

    public function getRetiredAt(): ?DateTimeImmutable
    {
        return $this->retiredAt;
    }

    public function isRetired(): bool
    {
        return $this->retiredAt instanceof DateTimeImmutable;
    }

    public function getSignedToken(): ?string
    {
        return $this->signedToken;
    }

    public function getSignedTokenContentHash(): string
    {
        return $this->signedTokenContentHash;
    }

    public function getSignedTokenIssuedAt(): ?DateTimeImmutable
    {
        return $this->signedTokenIssuedAt;
    }

    public function getSignedTokenExpiresAt(): ?DateTimeImmutable
    {
        return $this->signedTokenExpiresAt;
    }

    public function getCreatedAt(): ?DateTimeImmutable
    {
        return $this->createdAt;
    }

    /**
     * The value a signer must still find on the row for its token to be publishable.
     */
    public function getInvalidationCounter(): int
    {
        return $this->invalidationCounter;
    }

    /**
     * Whether a published token exists which can be served as-is.
     */
    public function hasPublishedToken(): bool
    {
        return $this->signedTokenContentHash !== '' &&
        is_string($this->signedToken) &&
        $this->signedToken !== '';
    }

    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::asString($row, 'id'),
            self::asString($row, 'uri'),
            self::asString($row, 'pool_id'),
            self::asString($row, 'policy_fingerprint'),
            self::asExpiryLane($row, 'expiry_lane'),
            self::asInt($row, 'generation'),
            self::asInt($row, 'bits'),
            self::asInt($row, 'capacity'),
            self::asString($row, 'allowed_statuses'),
            self::asInt($row, 'ttl_seconds'),
            self::asInt($row, 'token_validity_seconds'),
            self::asInt($row, 'refresh_interval_seconds'),
            self::asString($row, 'signing_key_id'),
            self::asKeyProfile($row, 'key_profile'),
            self::asInt($row, 'allocated_count'),
            self::asBool($row, 'is_active'),
            self::asNullableDateTime($row, 'deactivated_at'),
            self::asNullableDateTime($row, 'retired_at'),
            self::asNullableString($row, 'signed_token'),
            // Written NOT NULL DEFAULT '', but a row created before that default existed, or by hand,
            // would still read as null; treating it as "nothing published" is the safe reading.
            self::asNullableString($row, 'signed_token_content_hash') ?? '',
            self::asNullableDateTime($row, 'signed_token_iat'),
            self::asNullableDateTime($row, 'signed_token_exp'),
            self::asNullableDateTime($row, 'created_at'),
            // Added by a later migration than the table itself, so a row read while that migration has
            // not yet run has no such column. Zero is the value the column defaults to, which makes
            // such a read behave exactly as a list which has never been invalidated.
            self::asNullableInt($row, 'invalidation_counter') ?? 0,
        );
    }

    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected static function asKeyProfile(array $row, string $key): StatusListKeyProfileEnum
    {
        $value = self::asString($row, $key);

        return StatusListKeyProfileEnum::tryFrom($value) ?? throw new StatusListException(
            sprintf('Status List row column "%s" holds an unknown key profile "%s".', $key, $value),
        );
    }

    /**
     * Raised rather than defaulted, unlike the two columns above which tolerate a missing value.
     *
     * Those can: an absent invalidation counter reads as a list which has never been invalidated, and an
     * absent content hash as one with nothing published, both of which are true of the row in question.
     * A lane has no such reading. Guessing one would let a credential which never expires be allocated
     * into a list of credentials which do, which is the single thing the lane exists to prevent, and the
     * damage would be silent and permanent -- so an unreadable lane stops the allocation instead.
     *
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected static function asExpiryLane(array $row, string $key): StatusListExpiryLaneEnum
    {
        $value = self::asString($row, $key);

        return StatusListExpiryLaneEnum::tryFrom($value) ?? throw new StatusListException(
            sprintf('Status List row column "%s" holds an unknown expiry lane "%s".', $key, $value),
        );
    }
}
