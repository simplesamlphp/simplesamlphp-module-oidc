<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateTimeImmutable;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * One index within a Status List, and, while the credential occupying it is alive, what it was issued to.
 *
 * Every index of a list exists as a row from the moment the list is created, so a row is not evidence
 * that anything was issued: `allocated` is. Rows are never deleted while the list is served, since an
 * index which was handed out once must never be handed out again. What is deleted, once the credential
 * has expired, is the link back to it -- the credential ID, its hash, the subject reference and the
 * configuration -- leaving behind only the index and its status.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListEntryRecordTest
 */
class StatusListEntryRecord
{
    use DatabaseRowValuesTrait;

    /**
     * @param int $status Raw status value, which may be one this library does not name.
     * @param ?DateTimeImmutable $expiresAt When the credential occupying this index expires, or null
     * if it never does. A list holding a non-expiring entry can never be retired.
     * @param ?string $subjectRef Keyed hash of the user identifier, never the identifier itself.
     */
    public function __construct(
        protected readonly string $statusListId,
        protected readonly int $idx,
        protected readonly bool $allocated,
        protected readonly int $status,
        protected readonly ?DateTimeImmutable $expiresAt,
        protected readonly ?string $credentialId,
        protected readonly ?string $credentialIdHash,
        protected readonly ?string $credentialConfigurationId,
        protected readonly ?string $subjectRef,
        protected readonly ?DateTimeImmutable $issuedAt,
        protected readonly ?DateTimeImmutable $updatedAt,
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

    public function isAllocated(): bool
    {
        return $this->allocated;
    }

    public function getStatus(): int
    {
        return $this->status;
    }

    /**
     * The Status Type for this entry, or null when the stored value is application specific or not yet
     * registered. Callers deciding only whether the credential is usable should compare getStatus()
     * against zero instead, so that an unrecognised value is not mistaken for an absent one.
     */
    public function getStatusType(): ?StatusTypeEnum
    {
        return StatusTypeEnum::tryFrom($this->status);
    }

    public function getExpiresAt(): ?DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isNonExpiring(): bool
    {
        return !$this->expiresAt instanceof DateTimeImmutable;
    }

    public function getCredentialId(): ?string
    {
        return $this->credentialId;
    }

    public function getCredentialIdHash(): ?string
    {
        return $this->credentialIdHash;
    }

    public function getCredentialConfigurationId(): ?string
    {
        return $this->credentialConfigurationId;
    }

    public function getSubjectRef(): ?string
    {
        return $this->subjectRef;
    }

    public function getIssuedAt(): ?DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getUpdatedAt(): ?DateTimeImmutable
    {
        return $this->updatedAt;
    }

    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::asString($row, 'status_list_id'),
            self::asInt($row, 'idx'),
            self::asBool($row, 'allocated'),
            self::asInt($row, 'status'),
            self::asNullableDateTime($row, 'expires_at'),
            self::asNullableString($row, 'credential_id'),
            self::asNullableString($row, 'credential_id_hash'),
            self::asNullableString($row, 'credential_configuration_id'),
            self::asNullableString($row, 'subject_ref'),
            self::asNullableDateTime($row, 'issued_at'),
            self::asNullableDateTime($row, 'updated_at'),
        );
    }
}
