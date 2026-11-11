<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use DateTimeImmutable;
use DateTimeZone;
use JsonException;
use RuntimeException;
use Throwable;

/**
 * A Credential Offer as it is recorded, so that the API caller which made it can learn what it produced.
 *
 * It holds no personal data: the attributes of a pre-authorized offer travel with its code and its access token,
 * and go when they do. What it holds is who made the offer, what it offered, and the moments which decide how long
 * it is kept: until it can no longer be redeemed, and then for as long as an access token minted for it lives
 * ({@see \SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository}).
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values\CredentialOfferRecordTest
 */
class CredentialOfferRecord
{
    /**
     * @param string $id 64 lower-case hex characters, the only form an offer id is stored or accepted in.
     * @param ?string $owner The API principal which made the offer, as the API token principal resolver resolves
     * it; null for an offer made by an administrator, which no API caller owns.
     * @param list<string> $credentialConfigurationIds The configurations offered.
     * @param string $grantType The grant the offer is redeemed with.
     * @param \DateTimeImmutable $redeemableUntil When the pre-authorized code or the issuer state redeeming the
     * offer expires.
     * @param \DateTimeImmutable $retainedUntil Until when the record is kept at least: the moment it stops being
     * redeemable, raised to the expiry of every access token minted for it.
     * @param ?\DateTimeImmutable $redeemedAt When an access token was first minted for the offer. Not evidence that
     * a credential reached a wallet, and its absence proves nothing either.
     * @param ?\DateTimeImmutable $withdrawnAt When the offer was withdrawn, if it was.
     */
    public function __construct(
        protected readonly string $id,
        protected readonly ?string $owner,
        protected readonly array $credentialConfigurationIds,
        protected readonly string $grantType,
        protected readonly DateTimeImmutable $createdAt,
        protected readonly DateTimeImmutable $redeemableUntil,
        protected readonly DateTimeImmutable $retainedUntil,
        protected readonly ?DateTimeImmutable $redeemedAt = null,
        protected readonly ?DateTimeImmutable $withdrawnAt = null,
    ) {
    }


    public function getId(): string
    {
        return $this->id;
    }


    public function getOwner(): ?string
    {
        return $this->owner;
    }


    /**
     * @return list<string>
     */
    public function getCredentialConfigurationIds(): array
    {
        return $this->credentialConfigurationIds;
    }


    public function getGrantType(): string
    {
        return $this->grantType;
    }


    public function getCreatedAt(): DateTimeImmutable
    {
        return $this->createdAt;
    }


    public function getRedeemableUntil(): DateTimeImmutable
    {
        return $this->redeemableUntil;
    }


    public function getRetainedUntil(): DateTimeImmutable
    {
        return $this->retainedUntil;
    }


    public function getRedeemedAt(): ?DateTimeImmutable
    {
        return $this->redeemedAt;
    }


    public function getWithdrawnAt(): ?DateTimeImmutable
    {
        return $this->withdrawnAt;
    }


    /**
     * Whether the caller this principal names owns the offer. Compared here, byte for byte, never by the database:
     * MySQL's default collations ignore case and trailing spaces, which would make `HR system` and `hr system` one
     * owner. An offer no API caller made (an administrator's) is owned by none.
     */
    public function isOwnedBy(string $principal): bool
    {
        return $this->owner !== null && $this->owner === $principal;
    }


    /**
     * @param array<array-key,mixed> $row
     * @throws \RuntimeException When the row does not hold a credential offer record.
     */
    public static function fromRow(array $row): self
    {
        return new self(
            self::requiredString($row, 'id'),
            self::nullableString($row, 'owner'),
            self::credentialConfigurationIdsFrom($row),
            self::requiredString($row, 'grant_type'),
            self::requiredDateTime($row, 'created_at'),
            self::requiredDateTime($row, 'redeemable_until'),
            self::requiredDateTime($row, 'retained_until'),
            self::nullableDateTime($row, 'redeemed_at'),
            self::nullableDateTime($row, 'withdrawn_at'),
        );
    }


    /**
     * @param array<array-key,mixed> $row
     * @return list<string>
     * @throws \RuntimeException
     */
    protected static function credentialConfigurationIdsFrom(array $row): array
    {
        $encoded = self::requiredString($row, 'credential_configuration_ids');

        try {
            /** @var mixed $ids */
            $ids = json_decode($encoded, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $ids = null;
        }

        if (!is_array($ids) || !array_is_list($ids)) {
            throw new RuntimeException('Credential offer record holds malformed credential configuration IDs.');
        }

        $list = [];
        /** @var mixed $id */
        foreach ($ids as $id) {
            if (!is_string($id)) {
                throw new RuntimeException('Credential offer record holds malformed credential configuration IDs.');
            }

            $list[] = $id;
        }

        return $list;
    }


    /**
     * @param array<array-key,mixed> $row
     * @throws \RuntimeException
     */
    protected static function requiredString(array $row, string $key): string
    {
        return self::nullableString($row, $key) ??
        throw new RuntimeException(sprintf('Credential offer record is missing "%s".', $key));
    }


    /**
     * @param array<array-key,mixed> $row
     */
    protected static function nullableString(array $row, string $key): ?string
    {
        /** @var mixed $value */
        $value = $row[$key] ?? null;

        return is_string($value) ? $value : null;
    }


    /**
     * @param array<array-key,mixed> $row
     * @throws \RuntimeException
     */
    protected static function requiredDateTime(array $row, string $key): DateTimeImmutable
    {
        return self::nullableDateTime($row, $key) ??
        throw new RuntimeException(sprintf('Credential offer record is missing "%s".', $key));
    }


    /**
     * Moments are stored in UTC without a zone, so the zone is supplied here rather than left to the server's
     * default. A blank value is malformed, not a moment and not an absent one: the parser would read it as the
     * current time, which would say, for instance, that an offer was redeemed just now. The repository writes NULL
     * for a moment an offer does not have, never a blank.
     *
     * @param array<array-key,mixed> $row
     * @throws \RuntimeException When the value is there and is not a moment.
     */
    protected static function nullableDateTime(array $row, string $key): ?DateTimeImmutable
    {
        $value = self::nullableString($row, $key);

        if ($value === null) {
            return null;
        }

        if (trim($value) === '') {
            throw new RuntimeException(sprintf('Credential offer record holds a blank "%s".', $key));
        }

        try {
            return new DateTimeImmutable($value, new DateTimeZone('UTC'));
        } catch (Throwable) {
            throw new RuntimeException(sprintf('Credential offer record holds a malformed "%s".', $key));
        }
    }
}
