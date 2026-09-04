<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateInterval;
use DateTimeImmutable;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use SimpleSAML\OpenID\TokenStatusList\StatusList;
use Throwable;

/**
 * The policy a group of credential configurations shares when their Status List entries are allocated.
 *
 * A pool, not a credential configuration, is the unit which shares a Status List. Privacy scales with
 * the number of Referenced Tokens sharing a list (draft-ietf-oauth-status-list, Herd Privacy), so
 * splitting configurations across pools costs herd size and should be done only when their policies
 * genuinely differ. Several configurations therefore map onto one pool, which is why the credential
 * configuration ID is recorded on the entry row rather than being derivable from the pool.
 *
 * A pool is not quite the same thing as one list, though. Credentials which never expire are allocated
 * into lists of their own (see StatusListExpiryLaneEnum), so a pool whose configurations differ in
 * whether they have a lifetime keeps a list in each lane. That splits its herd, and the alternative is
 * worse: a list holding both kinds can never be retired, so nothing in such a pool would ever be.
 *
 * Instances are immutable and validated on construction, so holding one means the policy is coherent.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListPoolTest
 */
class StatusListPool
{
    /** Config key holding the credential configuration IDs which allocate from this pool. */
    final public const string KEY_CREDENTIAL_CONFIGURATIONS = 'credential_configurations';

    final public const string KEY_BITS = 'bits';

    final public const string KEY_CAPACITY = 'capacity';

    final public const string KEY_ALLOWED_STATUSES = 'allowed_statuses';

    final public const string KEY_TTL = 'ttl';

    final public const string KEY_TOKEN_VALIDITY = 'token_validity';

    final public const string KEY_REFRESH_INTERVAL = 'refresh_interval';

    final public const string KEY_KEY_PROFILE = 'key_profile';

    /**
     * One bit per Referenced Token, which is all a pool emitting only Valid and Invalid needs. This
     * affects transfer size, never herd size: the number of credentials sharing the list is what
     * privacy rests on, and that is set by the capacity.
     */
    final public const int DEFAULT_BITS = 1;

    /** 2^17, divisible by 8 as the specification recommends for the list size. */
    final public const int DEFAULT_CAPACITY = 131072;

    final public const string DEFAULT_TTL = 'PT12H';

    final public const string DEFAULT_TOKEN_VALIDITY = 'P7D';

    final public const string DEFAULT_REFRESH_INTERVAL = 'PT1H';

    /**
     * How long before a published token expires the publisher starts trying to replace it.
     *
     * This exists to keep a token from expiring while it is still the current published one. The
     * constraint validated below -- refresh interval plus this margin staying under the token
     * validity -- is what keeps a gap from opening up between one token expiring and the next being
     * produced, which is a mistake that has been shipped in a comparable implementation.
     */
    final public const string SAFETY_MARGIN = 'PT15M';

    /**
     * The capacity must be a whole number of bytes' worth of entries, so that the list conveys a
     * status for exactly as many indices as it was configured for. Requiring a multiple of 8 satisfies
     * that for every allowed `bits`, and is what the specification recommends for the list size anyway.
     */
    protected const int CAPACITY_MULTIPLE = 8;


    /**
     * @param string $id Pool identifier, being the key it is configured under.
     * @param string[] $credentialConfigurationIds Credential configurations which allocate from this pool.
     * @param \SimpleSAML\OpenID\Codebooks\StatusTypeEnum[] $allowedStatuses Statuses this pool may
     * emit. Always includes Valid, since an entry has to be able to return to it.
     * @param ?string $issuerIdentifier The deployment's issuer `did:web`, required by that key profile
     * and unused by every other. Taken from the module wide issuer identity rather than configured per
     * pool: a deployment has one such identity, and letting a pool name a second would leave one of
     * them without the published DID document a Relying Party has to resolve.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function __construct(
        protected readonly string $id,
        protected readonly array $credentialConfigurationIds,
        protected readonly int $bits,
        protected readonly int $capacity,
        protected readonly array $allowedStatuses,
        protected readonly DateInterval $ttl,
        protected readonly DateInterval $tokenValidity,
        protected readonly DateInterval $refreshInterval,
        protected readonly StatusListKeyProfileEnum $keyProfile,
        protected readonly ?string $issuerIdentifier = null,
    ) {
        $this->validate();
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function validate(): void
    {
        if ($this->id === '') {
            throw new ConfigurationError('Status List pool identifier must not be empty.');
        }

        if ($this->credentialConfigurationIds === []) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" lists no credential configurations, so nothing would ever ' .
                    'allocate from it. Remove the pool, or add the credential configuration IDs which ' .
                    'should use it under "%s".',
                    $this->id,
                    self::KEY_CREDENTIAL_CONFIGURATIONS,
                ),
            );
        }

        // Refused while the pool is being built, rather than left to fail when a token is signed: by
        // then the list exists and credentials already point at it. The option is named through its
        // constant so that renaming it can not leave this message pointing at something gone.
        if ($this->keyProfile === StatusListKeyProfileEnum::DidWeb && $this->issuerIdentifier === null) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" signs under the "%s" key profile, which names the issuer by ' .
                    'a `did:web` identifier, but "%s" is not set. Set it, or move the pool to another ' .
                    '"%s".',
                    $this->id,
                    StatusListKeyProfileEnum::DidWeb->value,
                    ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
                    self::KEY_KEY_PROFILE,
                ),
            );
        }

        if (!StatusList::isAllowedBits($this->bits)) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" is configured with %d bit(s) per Referenced Token, expected ' .
                    'one of: %s.',
                    $this->id,
                    $this->bits,
                    implode(', ', StatusList::ALLOWED_BITS),
                ),
            );
        }

        if ($this->capacity < 1 || $this->capacity % self::CAPACITY_MULTIPLE !== 0) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" is configured with a capacity of %d, which must be a ' .
                    'positive multiple of %d.',
                    $this->id,
                    $this->capacity,
                    self::CAPACITY_MULTIPLE,
                ),
            );
        }

        // The number of bits fixes the largest status the list can carry at all, and reconfiguring it
        // later can not retrofit lists which already exist. A pool which may suspend therefore needs
        // to say so up front.
        $largestRepresentable = (1 << $this->bits) - 1;

        foreach ($this->allowedStatuses as $status) {
            if ($status->value > $largestRepresentable) {
                throw new ConfigurationError(
                    sprintf(
                        'Status List pool "%s" allows the status %s (0x%02X), which can not be ' .
                        'represented using %d bit(s) per Referenced Token (largest is 0x%02X). Raise ' .
                        '"%s" to at least %d, or remove the status.',
                        $this->id,
                        $status->name,
                        $status->value,
                        $this->bits,
                        $largestRepresentable,
                        self::KEY_BITS,
                        $status->requiredBits(),
                    ),
                );
            }
        }

        $ttlSeconds = self::toSeconds($this->ttl);

        if ($ttlSeconds < 1) {
            throw new ConfigurationError(
                sprintf('Status List pool "%s" must have a positive "%s".', $this->id, self::KEY_TTL),
            );
        }

        $refreshSeconds = self::toSeconds($this->refreshInterval);
        $validitySeconds = self::toSeconds($this->tokenValidity);
        $marginSeconds = self::toSeconds(new DateInterval(self::SAFETY_MARGIN));

        if ($refreshSeconds < 1) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" must have a positive "%s".',
                    $this->id,
                    self::KEY_REFRESH_INTERVAL,
                ),
            );
        }

        // Getting this the wrong way round leaves a recurring window in every cycle during which the
        // published token has expired and its replacement has not been produced yet, so the endpoint
        // has nothing valid to serve.
        if ($refreshSeconds + $marginSeconds >= $validitySeconds) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" refreshes every %d second(s) but its tokens are only valid ' .
                    'for %d second(s). The refresh interval plus the %d second safety margin must stay ' .
                    'below the token validity, otherwise a published token expires before its ' .
                    'replacement is produced. Raise "%s" or lower "%s".',
                    $this->id,
                    $refreshSeconds,
                    $validitySeconds,
                    $marginSeconds,
                    self::KEY_TOKEN_VALIDITY,
                    self::KEY_REFRESH_INTERVAL,
                ),
            );
        }
    }


    /**
     * How many seconds a duration is worth, measured from a fixed point rather than from now.
     *
     * A DateInterval has no length until something anchors it, and anchoring it to the current moment
     * in the server's timezone makes the answer move: across a daylight saving transition, P7D is worth
     * an hour more or less than it is the rest of the year. That number goes into the policy
     * fingerprint, so an unchanged configuration would fingerprint differently on either side of a
     * transition and quietly move every pool onto fresh lists, splitting the herd for no reason.
     * Anchoring to the epoch in UTC removes both the timezone and the moving reference, so the same
     * configuration always yields the same number.
     */
    protected static function toSeconds(DateInterval $interval): int
    {
        return (new DateTimeImmutable('@0'))->add($interval)->getTimestamp();
    }


    public function getId(): string
    {
        return $this->id;
    }


    /**
     * @return string[]
     */
    public function getCredentialConfigurationIds(): array
    {
        return $this->credentialConfigurationIds;
    }


    public function hasCredentialConfigurationId(string $credentialConfigurationId): bool
    {
        return in_array($credentialConfigurationId, $this->credentialConfigurationIds, true);
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
     * @return \SimpleSAML\OpenID\Codebooks\StatusTypeEnum[]
     */
    public function getAllowedStatuses(): array
    {
        return $this->allowedStatuses;
    }


    public function isStatusAllowed(StatusTypeEnum $status): bool
    {
        return in_array($status, $this->allowedStatuses, true);
    }


    /**
     * The allowed statuses in the form persisted on the Status List row, being their values in
     * ascending order and comma separated.
     */
    public function getAllowedStatusesAsString(): string
    {
        $values = array_map(
            static fn(StatusTypeEnum $status): int => $status->value,
            $this->allowedStatuses,
        );

        sort($values);

        return implode(',', $values);
    }


    public function getTtl(): DateInterval
    {
        return $this->ttl;
    }


    public function getTtlInSeconds(): int
    {
        return self::toSeconds($this->ttl);
    }


    public function getTokenValidity(): DateInterval
    {
        return $this->tokenValidity;
    }


    public function getTokenValidityInSeconds(): int
    {
        return self::toSeconds($this->tokenValidity);
    }


    public function getRefreshInterval(): DateInterval
    {
        return $this->refreshInterval;
    }


    public function getRefreshIntervalInSeconds(): int
    {
        return self::toSeconds($this->refreshInterval);
    }


    public function getKeyProfile(): StatusListKeyProfileEnum
    {
        return $this->keyProfile;
    }


    /**
     * The issuer `did:web` a list created from this pool is stamped with, or null under the profiles
     * which identify the issuer some other way.
     */
    public function getIssuerIdentifier(): ?string
    {
        return $this->issuerIdentifier;
    }


    /**
     * Hash of the immutable part of this pool's policy, which allocation filters candidate lists on.
     *
     * Without it, changing a pool setting would leave lists created under the old settings eligible for
     * new allocations. The signing key is part of the tuple for the same reason: during a key rotation
     * the issuer signs credentials with the current key, and a list still bound to the previous one
     * would quietly break the profile which says the two are the same key. The key profile is included
     * so that changing which identifier tokens carry routes new credentials to new lists, leaving
     * existing lists to be served under the profile their holders already resolved them by.
     *
     * The refresh interval is deliberately absent: it governs when a token is re-signed, not what any
     * credential in the list resolves to, so changing it must not strand a half-full list.
     *
     * @throws \JsonException
     */
    public function getPolicyFingerprint(string $signingKeyId): string
    {
        $policy = [
            'bits' => $this->bits,
            'capacity' => $this->capacity,
            'signing_key_id' => $signingKeyId,
            'allowed_statuses' => $this->getAllowedStatusesAsString(),
            'ttl_seconds' => $this->getTtlInSeconds(),
            'token_validity_seconds' => $this->getTokenValidityInSeconds(),
            'key_profile' => $this->keyProfile->value,
        ];

        // Included only under the profile which uses it, so that a pool on any other profile hashes
        // the same bytes it hashed before this one existed. Adding the key unconditionally -- even as
        // null -- would move every existing pool onto fresh lists at once, splitting herds which had
        // no reason to split. Under `did_web` it has to be here: a list records the identifier it was
        // created with, so changing that identifier must route new credentials to a new list rather
        // than onto one whose tokens still name the issuer it was created under.
        if ($this->keyProfile === StatusListKeyProfileEnum::DidWeb) {
            $policy['issuer_identifier'] = $this->issuerIdentifier;
        }

        return hash('sha256', json_encode($policy, JSON_THROW_ON_ERROR));
    }


    /**
     * Builds a pool from its configured settings, applying the defaults for everything left out.
     *
     * @param array<array-key,mixed> $config
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public static function fromConfig(
        string $id,
        array $config,
        StatusListKeyProfileEnum $defaultKeyProfile,
        ?string $issuerIdentifier = null,
    ): self {
        $keyProfile = self::resolveKeyProfile($id, $config, $defaultKeyProfile);

        return new self(
            $id,
            self::resolveCredentialConfigurationIds($id, $config),
            self::resolveInt($id, $config, self::KEY_BITS, self::DEFAULT_BITS),
            self::resolveInt($id, $config, self::KEY_CAPACITY, self::DEFAULT_CAPACITY),
            self::resolveAllowedStatuses($id, $config),
            self::resolveInterval($id, $config, self::KEY_TTL, self::DEFAULT_TTL),
            self::resolveInterval($id, $config, self::KEY_TOKEN_VALIDITY, self::DEFAULT_TOKEN_VALIDITY),
            self::resolveInterval($id, $config, self::KEY_REFRESH_INTERVAL, self::DEFAULT_REFRESH_INTERVAL),
            $keyProfile,
            // Carried only by the profile which uses it. The caller resolves the identifier as soon as
            // any one pool needs it, and a deployment may well mix profiles, so handing it to the rest
            // would have them stamp every list they create with an identity nothing will ever resolve
            // from it -- and a later reader asking which DID documents still have to be published would
            // read those rows and name one that was never needed.
            $keyProfile === StatusListKeyProfileEnum::DidWeb ? $issuerIdentifier : null,
        );
    }


    /**
     * @param array<array-key,mixed> $config
     * @return string[]
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected static function resolveCredentialConfigurationIds(string $id, array $config): array
    {
        /** @var mixed $ids */
        $ids = $config[self::KEY_CREDENTIAL_CONFIGURATIONS] ?? [];

        if (!is_array($ids)) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" has a "%s" which is not an array.',
                    $id,
                    self::KEY_CREDENTIAL_CONFIGURATIONS,
                ),
            );
        }

        /** @var mixed $credentialConfigurationId */
        foreach ($ids as $credentialConfigurationId) {
            if (!is_string($credentialConfigurationId) || $credentialConfigurationId === '') {
                throw new ConfigurationError(
                    sprintf(
                        'Status List pool "%s" lists a credential configuration ID which is not a ' .
                        'non-empty string.',
                        $id,
                    ),
                );
            }
        }

        /** @var string[] $ids */
        return array_values(array_unique($ids));
    }


    /**
     * @param array<array-key,mixed> $config
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected static function resolveInt(string $id, array $config, string $key, int $default): int
    {
        if (!array_key_exists($key, $config)) {
            return $default;
        }

        /** @var mixed $value */
        $value = $config[$key];

        if (!is_int($value)) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" has a "%s" which is not an integer, %s given.',
                    $id,
                    $key,
                    get_debug_type($value),
                ),
            );
        }

        return $value;
    }


    /**
     * @param array<array-key,mixed> $config
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected static function resolveInterval(
        string $id,
        array $config,
        string $key,
        string $default,
    ): DateInterval {
        /** @var mixed $value */
        $value = $config[$key] ?? $default;

        if (!is_string($value)) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" has a "%s" which is not a duration string, %s given.',
                    $id,
                    $key,
                    get_debug_type($value),
                ),
            );
        }

        try {
            return new DateInterval($value);
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" has a "%s" which is not a valid duration: %s',
                    $id,
                    $key,
                    $throwable->getMessage(),
                ),
            );
        }
    }


    /**
     * @param array<array-key,mixed> $config
     * @return \SimpleSAML\OpenID\Codebooks\StatusTypeEnum[]
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected static function resolveAllowedStatuses(string $id, array $config): array
    {
        /** @var mixed $configured */
        $configured = $config[self::KEY_ALLOWED_STATUSES] ?? [StatusTypeEnum::Invalid];

        if (!is_array($configured)) {
            throw new ConfigurationError(
                sprintf(
                    'Status List pool "%s" has an "%s" which is not an array.',
                    $id,
                    self::KEY_ALLOWED_STATUSES,
                ),
            );
        }

        // Valid is always allowed, whether or not it was configured: an entry which can be revoked has
        // to be able to be reinstated, and an unallocated index reads as Valid regardless.
        $statuses = [StatusTypeEnum::Valid];

        /** @var mixed $status */
        foreach ($configured as $status) {
            // Integers are accepted as a convenience, but only ones which name a registered Status
            // Type. A string is not: casting one to an integer turns every typo into 0, which is
            // Valid, so a misspelt status would silently configure the pool to allow nothing.
            if (is_int($status)) {
                $status = StatusTypeEnum::tryFrom($status) ?? $status;
            }

            if (!$status instanceof StatusTypeEnum) {
                throw new ConfigurationError(
                    sprintf(
                        'Status List pool "%s" allows a status which is not a %s case: %s.',
                        $id,
                        StatusTypeEnum::class,
                        var_export($status, true),
                    ),
                );
            }

            if (!in_array($status, $statuses, true)) {
                $statuses[] = $status;
            }
        }

        return $statuses;
    }


    /**
     * @param array<array-key,mixed> $config
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected static function resolveKeyProfile(
        string $id,
        array $config,
        StatusListKeyProfileEnum $default,
    ): StatusListKeyProfileEnum {
        if (!array_key_exists(self::KEY_KEY_PROFILE, $config)) {
            return $default;
        }

        /** @var mixed $value */
        $value = $config[self::KEY_KEY_PROFILE];

        if ($value instanceof StatusListKeyProfileEnum) {
            return $value;
        }

        if (is_string($value) && ($profile = StatusListKeyProfileEnum::tryFrom($value)) !== null) {
            return $profile;
        }

        throw new ConfigurationError(
            sprintf(
                'Status List pool "%s" has a "%s" which is not one of: %s.',
                $id,
                self::KEY_KEY_PROFILE,
                implode(
                    ', ',
                    array_map(
                        static fn(StatusListKeyProfileEnum $case): string => $case->value,
                        StatusListKeyProfileEnum::cases(),
                    ),
                ),
            ),
        );
    }
}
