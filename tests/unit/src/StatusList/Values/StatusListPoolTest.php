<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusListPool::class)]
class StatusListPoolTest extends TestCase
{
    protected const string POOL_ID = 'default';

    protected const string KEY_ID = 'signing-key-1';

    /**
     * @param array<array-key,mixed> $overrides
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function sut(
        array $overrides = [],
        StatusListKeyProfileEnum $defaultKeyProfile = StatusListKeyProfileEnum::DidJwk,
    ): StatusListPool {
        return StatusListPool::fromConfig(
            self::POOL_ID,
            array_merge(
                [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['SomeCredential']],
                $overrides,
            ),
            $defaultKeyProfile,
        );
    }

    public function testAppliesDefaultsForEverythingNotConfigured(): void
    {
        $pool = $this->sut();

        $this->assertSame(StatusListPool::DEFAULT_BITS, $pool->getBits());
        $this->assertSame(StatusListPool::DEFAULT_CAPACITY, $pool->getCapacity());
        $this->assertSame(43200, $pool->getTtlInSeconds());
        $this->assertSame(604800, $pool->getTokenValidityInSeconds());
        $this->assertSame(3600, $pool->getRefreshIntervalInSeconds());
        $this->assertSame(StatusListKeyProfileEnum::DidJwk, $pool->getKeyProfile());
        $this->assertSame(['SomeCredential'], $pool->getCredentialConfigurationIds());
    }

    public function testDefaultCapacityIsDivisibleByEight(): void
    {
        // The specification recommends this for the list size, and it is what keeps the number of
        // indices the list conveys a status for equal to the capacity which was asked for.
        $this->assertSame(0, StatusListPool::DEFAULT_CAPACITY % 8);
    }

    public function testTakesTheGlobalKeyProfileAndAllowsAPoolToOverrideIt(): void
    {
        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $this->sut([], StatusListKeyProfileEnum::Jwks)->getKeyProfile(),
        );

        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $this->sut(
                [StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks],
                StatusListKeyProfileEnum::DidJwk,
            )->getKeyProfile(),
        );

        // Also accepted as its string value, which is how a hand written config is likely to spell it.
        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $this->sut(
                [StatusListPool::KEY_KEY_PROFILE => 'jwks'],
                StatusListKeyProfileEnum::DidJwk,
            )->getKeyProfile(),
        );
    }

    public function testRejectsAnUnknownKeyProfile(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(StatusListPool::KEY_KEY_PROFILE);

        $this->sut([StatusListPool::KEY_KEY_PROFILE => 'x509']);
    }

    public function testRejectsAPoolWithNoCredentialConfigurations(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS);

        StatusListPool::fromConfig(self::POOL_ID, [], StatusListKeyProfileEnum::DidJwk);
    }

    /**
     * @return array<string,array{int}>
     */
    public static function invalidBitsProvider(): array
    {
        return ['zero' => [0], 'three' => [3], 'five' => [5], 'sixteen' => [16], 'negative' => [-1]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidBitsProvider')]
    public function testRejectsBitsWhichAreNotOneOfTheAllowedValues(int $bits): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([StatusListPool::KEY_BITS => $bits]);
    }

    public function testRejectsACapacityWhichIsNotAPositiveMultipleOfEight(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->sut([StatusListPool::KEY_CAPACITY => 100]);
    }

    public function testRejectsANonPositiveCapacity(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->sut([StatusListPool::KEY_CAPACITY => 0]);
    }

    /**
     * The number of bits fixes the largest status a list can ever carry, and reconfiguring it later
     * can not retrofit lists which already exist. A pool which may suspend has to say so up front.
     */
    public function testRejectsAStatusWhichDoesNotFitTheConfiguredBits(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Suspended');

        $this->sut([
            StatusListPool::KEY_BITS => 1,
            StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Suspended],
        ]);
    }

    public function testAcceptsSuspendedOnceThereAreEnoughBits(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Invalid, StatusTypeEnum::Suspended],
        ]);

        $this->assertTrue($pool->isStatusAllowed(StatusTypeEnum::Suspended));
    }

    /**
     * An entry which can be revoked has to be able to be reinstated, and an index which was never
     * allocated reads as Valid regardless of configuration.
     */
    public function testAlwaysAllowsValidEvenWhenItWasNotConfigured(): void
    {
        $pool = $this->sut([StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Invalid]]);

        $this->assertTrue($pool->isStatusAllowed(StatusTypeEnum::Valid));
        $this->assertSame('0,1', $pool->getAllowedStatusesAsString());
    }

    public function testAcceptsAStatusGivenAsItsRegisteredIntegerValue(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_ALLOWED_STATUSES => [1, 2],
        ]);

        $this->assertTrue($pool->isStatusAllowed(StatusTypeEnum::Suspended));
        $this->assertSame('0,1,2', $pool->getAllowedStatusesAsString());
    }

    /**
     * Casting a string to an integer turns every typo into 0, which is Valid, so a misspelt status
     * would silently configure the pool to allow nothing rather than being reported.
     */
    public function testRejectsAStatusGivenAsAString(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([StatusListPool::KEY_ALLOWED_STATUSES => ['invalid']]);
    }

    public function testRejectsAnUnregisteredStatusValue(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([StatusListPool::KEY_BITS => 4, StatusListPool::KEY_ALLOWED_STATUSES => [7]]);
    }

    /**
     * Getting this the wrong way round leaves a recurring window in every cycle where the published
     * token has expired and its replacement has not been produced yet.
     */
    public function testRejectsARefreshIntervalWhichDoesNotFitInsideTheTokenValidity(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(StatusListPool::KEY_TOKEN_VALIDITY);

        $this->sut([
            StatusListPool::KEY_REFRESH_INTERVAL => 'PT1H',
            StatusListPool::KEY_TOKEN_VALIDITY => 'PT1H',
        ]);
    }

    public function testRejectsARefreshIntervalLeavingLessThanTheSafetyMargin(): void
    {
        $this->expectException(ConfigurationError::class);

        // Ten minutes of headroom, where the safety margin asks for fifteen.
        $this->sut([
            StatusListPool::KEY_REFRESH_INTERVAL => 'PT50M',
            StatusListPool::KEY_TOKEN_VALIDITY => 'PT1H',
        ]);
    }

    public function testAcceptsARefreshIntervalWithEnoughHeadroom(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_REFRESH_INTERVAL => 'PT30M',
            StatusListPool::KEY_TOKEN_VALIDITY => 'PT2H',
        ]);

        $this->assertSame(1800, $pool->getRefreshIntervalInSeconds());
    }

    public function testRejectsAnUnparsableDuration(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([StatusListPool::KEY_TTL => 'twelve hours']);
    }

    public function testRejectsANonIntegerBitsValue(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut([StatusListPool::KEY_BITS => '2']);
    }

    public function testTellsWhichCredentialConfigurationsItServes(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['A', 'B', 'A'],
        ]);

        $this->assertSame(['A', 'B'], $pool->getCredentialConfigurationIds());
        $this->assertTrue($pool->hasCredentialConfigurationId('B'));
        $this->assertFalse($pool->hasCredentialConfigurationId('C'));
    }

    public function testPolicyFingerprintIsStableForTheSamePolicy(): void
    {
        $this->assertSame(
            $this->sut()->getPolicyFingerprint(self::KEY_ID),
            $this->sut()->getPolicyFingerprint(self::KEY_ID),
        );
    }

    /**
     * A duration has no length until something anchors it, and anchoring it to "now" in a timezone
     * which observes daylight saving makes P7D worth an hour more or less at certain times of year.
     * That number goes into the policy fingerprint, so an unchanged configuration would fingerprint
     * differently across a transition and quietly move every pool onto fresh lists.
     */
    public function testDurationsDoNotDependOnTheServerTimezoneOrTheCurrentDate(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            $seenTtl = [];
            $seenValidity = [];

            // Zones on both sides of UTC, one of which is deep in a daylight saving change window.
            foreach (['UTC', 'Europe/Zagreb', 'America/Santiago', 'Pacific/Chatham'] as $timezone) {
                date_default_timezone_set($timezone);

                $pool = $this->sut();
                $seenTtl[] = $pool->getTtlInSeconds();
                $seenValidity[] = $pool->getTokenValidityInSeconds();
            }

            $this->assertSame([43200, 43200, 43200, 43200], $seenTtl);
            $this->assertSame([604800, 604800, 604800, 604800], $seenValidity);
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }

    /**
     * The same, seen through the value which actually matters: the fingerprint allocation filters on.
     */
    public function testPolicyFingerprintDoesNotDependOnTheServerTimezone(): void
    {
        $originalTimezone = date_default_timezone_get();

        try {
            date_default_timezone_set('UTC');
            $inUtc = $this->sut()->getPolicyFingerprint(self::KEY_ID);

            date_default_timezone_set('America/Santiago');
            $inSantiago = $this->sut()->getPolicyFingerprint(self::KEY_ID);

            $this->assertSame($inUtc, $inSantiago);
        } finally {
            date_default_timezone_set($originalTimezone);
        }
    }

    /**
     * @return array<string,array{array<array-key,mixed>}>
     */
    public static function policyChangingOverrideProvider(): array
    {
        return [
            'bits' => [[StatusListPool::KEY_BITS => 2]],
            'capacity' => [[StatusListPool::KEY_CAPACITY => 256]],
            'ttl' => [[StatusListPool::KEY_TTL => 'PT6H']],
            'token validity' => [[StatusListPool::KEY_TOKEN_VALIDITY => 'P14D']],
            'allowed statuses' => [[
                StatusListPool::KEY_BITS => 2,
                StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Suspended],
            ]],
            'key profile' => [[StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks]],
        ];
    }

    /**
     * @param array<array-key,mixed> $override
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('policyChangingOverrideProvider')]
    public function testPolicyFingerprintChangesWithAnySettingBakedIntoALists(array $override): void
    {
        $this->assertNotSame(
            $this->sut()->getPolicyFingerprint(self::KEY_ID),
            $this->sut($override)->getPolicyFingerprint(self::KEY_ID),
        );
    }

    /**
     * During a key rotation the issuer signs credentials with the current key, so a list still bound to
     * the previous one must stop being selected, or the profile saying the two are the same key breaks.
     */
    public function testPolicyFingerprintChangesWithTheSigningKey(): void
    {
        $this->assertNotSame(
            $this->sut()->getPolicyFingerprint(self::KEY_ID),
            $this->sut()->getPolicyFingerprint('signing-key-2'),
        );
    }

    /**
     * The refresh interval governs when a token is re-signed, not what any credential resolves to, so
     * changing it must not strand a half filled list.
     */
    public function testPolicyFingerprintIgnoresTheRefreshInterval(): void
    {
        $this->assertSame(
            $this->sut([StatusListPool::KEY_REFRESH_INTERVAL => 'PT1H'])
                ->getPolicyFingerprint(self::KEY_ID),
            $this->sut([StatusListPool::KEY_REFRESH_INTERVAL => 'PT30M'])
                ->getPolicyFingerprint(self::KEY_ID),
        );
    }

    /**
     * The pool a credential belongs to is not part of what a list carries, but two pools sharing a
     * fingerprint would let one pool's credentials be allocated into the other's list.
     */
    public function testPolicyFingerprintIsNotSharedBetweenPoolsWithDifferentAllowedStatuses(): void
    {
        $narrow = $this->sut([StatusListPool::KEY_BITS => 2]);
        $wide = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Invalid, StatusTypeEnum::Suspended],
        ]);

        $this->assertNotSame(
            $narrow->getPolicyFingerprint(self::KEY_ID),
            $wide->getPolicyFingerprint(self::KEY_ID),
        );
    }
}
