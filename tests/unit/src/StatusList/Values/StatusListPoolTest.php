<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(StatusListPool::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListPoolTest extends TestCase
{
    protected const string POOL_ID = 'default';

    protected const string KEY_ID = 'signing-key-1';

    protected const string DID_WEB = 'did:web:issuer.example.org';


    /**
     * @param array<array-key,mixed> $overrides
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function sut(
        array $overrides = [],
        StatusListKeyProfileEnum $defaultKeyProfile = StatusListKeyProfileEnum::DidJwk,
        ?string $issuerIdentifier = null,
    ): StatusListPool {
        return StatusListPool::fromConfig(
            self::POOL_ID,
            array_merge(
                [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['SomeCredential']],
                $overrides,
            ),
            $defaultKeyProfile,
            $issuerIdentifier,
        );
    }


    /**
     * The refusals are written for the operator, most of them naming the key to raise, lower or set,
     * so the reason is pinned whole rather than the refusal alone.
     *
     * @param callable(): \SimpleSAML\Module\oidc\StatusList\Values\StatusListPool $build
     */
    protected function assertRefusedBecause(string $reason, callable $build): void
    {
        try {
            $build();
        } catch (ConfigurationError $e) {
            $this->assertSame($reason, $e->getReason());
            return;
        }

        $this->fail('A ConfigurationError was expected.');
    }


    public function testAppliesDefaultsForEverythingNotConfigured(): void
    {
        $pool = $this->sut();

        $this->assertSame(StatusListPool::DEFAULT_BITS, $pool->getBits());
        $this->assertSame(StatusListPool::DEFAULT_CAPACITY, $pool->getCapacity());
        $this->assertSame([StatusTypeEnum::Valid, StatusTypeEnum::Invalid], $pool->getAllowedStatuses());
        $this->assertSame('0,1', $pool->getAllowedStatusesAsString());
        $this->assertEquals(new DateInterval(StatusListPool::DEFAULT_TTL), $pool->getTtl());
        $this->assertSame(43200, $pool->getTtlInSeconds());
        $this->assertEquals(new DateInterval(StatusListPool::DEFAULT_TOKEN_VALIDITY), $pool->getTokenValidity());
        $this->assertSame(604800, $pool->getTokenValidityInSeconds());
        $this->assertEquals(new DateInterval(StatusListPool::DEFAULT_REFRESH_INTERVAL), $pool->getRefreshInterval());
        $this->assertSame(3600, $pool->getRefreshIntervalInSeconds());
        $this->assertSame(StatusListKeyProfileEnum::DidJwk, $pool->getKeyProfile());
        $this->assertNull($pool->getIssuerIdentifier());
    }


    public function testExposesTheConfiguredValuesAsGiven(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_CAPACITY => 1024,
            StatusListPool::KEY_TTL => 'PT6H',
            StatusListPool::KEY_TOKEN_VALIDITY => 'P14D',
            StatusListPool::KEY_REFRESH_INTERVAL => 'PT30M',
        ]);

        $this->assertSame(self::POOL_ID, $pool->getId());
        $this->assertSame(2, $pool->getBits());
        $this->assertSame(1024, $pool->getCapacity());
        $this->assertEquals(new DateInterval('PT6H'), $pool->getTtl());
        $this->assertSame(21600, $pool->getTtlInSeconds());
        $this->assertEquals(new DateInterval('P14D'), $pool->getTokenValidity());
        $this->assertSame(1209600, $pool->getTokenValidityInSeconds());
        $this->assertEquals(new DateInterval('PT30M'), $pool->getRefreshInterval());
        $this->assertSame(1800, $pool->getRefreshIntervalInSeconds());
    }


    public function testKeepsTheAllowedStatusesValidFirstThenAsConfiguredEachOnce(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_ALLOWED_STATUSES => [
                StatusTypeEnum::Suspended,
                StatusTypeEnum::Valid,
                StatusTypeEnum::Invalid,
                StatusTypeEnum::Invalid,
            ],
        ]);

        $this->assertSame(
            [StatusTypeEnum::Valid, StatusTypeEnum::Suspended, StatusTypeEnum::Invalid],
            $pool->getAllowedStatuses(),
        );
        // The persisted form sorts them regardless of that order.
        $this->assertSame('0,1,2', $pool->getAllowedStatusesAsString());
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


    /**
     * Refused while the pool is built rather than when a token is signed, because by then the list
     * exists and credentials already point at it.
     */
    public function testRejectsTheDidWebProfileWithNoIssuerIdentifier(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" signs under the "did_web" key profile, which names the issuer by ' .
            'a `did:web` identifier, but "' . ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER . '" is not ' .
            'set. Set it, or move the pool to another "key_profile".',
            fn (): StatusListPool => $this->sut(
                [StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb],
            ),
        );
    }


    public function testCarriesTheIssuerIdentifierUnderTheDidWebProfile(): void
    {
        $pool = $this->sut(
            [StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb],
            issuerIdentifier: self::DID_WEB,
        );

        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $pool->getKeyProfile());
        $this->assertSame(self::DID_WEB, $pool->getIssuerIdentifier());
    }


    /**
     * The identifier is resolved once for the whole bag, as soon as any one pool needs it, so a mixed
     * configuration hands it to pools which do not. They must not keep it: a list they create would
     * otherwise record an identity nothing resolves from it, and whoever later asks which DID documents
     * still have to be served would be told to keep one that was never needed.
     */
    #[DataProvider('profilesWhichDoNotUseTheIssuerIdentifierDataProvider')]
    public function testDoesNotCarryTheIssuerIdentifierUnderTheOtherProfiles(
        StatusListKeyProfileEnum $keyProfile,
    ): void {
        $pool = $this->sut(
            [StatusListPool::KEY_KEY_PROFILE => $keyProfile],
            issuerIdentifier: self::DID_WEB,
        );

        $this->assertSame($keyProfile, $pool->getKeyProfile());
        $this->assertNull($pool->getIssuerIdentifier());
    }


    public function testRejectsAnUnknownKeyProfile(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" has a "key_profile" which is not one of: did_jwk, did_web, jwks.',
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_KEY_PROFILE => 'x509']),
        );
    }


    public function testRejectsAnEmptyPoolIdentifier(): void
    {
        $this->assertRefusedBecause(
            'Status List pool identifier must not be empty.',
            fn (): StatusListPool => StatusListPool::fromConfig(
                '',
                [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['SomeCredential']],
                StatusListKeyProfileEnum::DidJwk,
            ),
        );
    }


    public function testRejectsAPoolWithNoCredentialConfigurations(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" lists no credential configurations, so nothing would ever ' .
            'allocate from it. Remove the pool, or add the credential configuration IDs which should use ' .
            'it under "credential_configurations".',
            fn (): StatusListPool => StatusListPool::fromConfig(
                self::POOL_ID,
                [],
                StatusListKeyProfileEnum::DidJwk,
            ),
        );
    }


    public function testRejectsCredentialConfigurationsWhichAreNotAnArray(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" has a "credential_configurations" which is not an array.',
            fn (): StatusListPool => $this->sut(
                [StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => 'SomeCredential'],
            ),
        );
    }


    /**
     * @return array<string,array{array<array-key,mixed>}>
     */
    public static function credentialConfigurationIdWhichIsNotANonEmptyStringProvider(): array
    {
        return [
            'an integer' => [[42]],
            'an empty string beside a proper one' => [['SomeCredential', '']],
        ];
    }


    /**
     * @param array<array-key,mixed> $ids
     */
    #[DataProvider('credentialConfigurationIdWhichIsNotANonEmptyStringProvider')]
    public function testRejectsACredentialConfigurationIdWhichIsNotANonEmptyString(array $ids): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" lists a credential configuration ID which is not a non-empty ' .
            'string.',
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => $ids]),
        );
    }


    /**
     * @return array<string,array{int}>
     */
    public static function invalidBitsProvider(): array
    {
        return [
            'below the floor' => [0],
            'negative' => [-1],
            'between two allowed values' => [3],
            'the next power of two' => [16],
        ];
    }


    #[DataProvider('invalidBitsProvider')]
    public function testRejectsBitsWhichAreNotOneOfTheAllowedValues(int $bits): void
    {
        $this->assertRefusedBecause(
            sprintf(
                'Status List pool "default" is configured with %d bit(s) per Referenced Token, expected ' .
                'one of: 1, 2, 4, 8.',
                $bits,
            ),
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_BITS => $bits]),
        );
    }


    /**
     * @return array<string,array{int}>
     */
    public static function invalidCapacityProvider(): array
    {
        return ['not a multiple of eight' => [100], 'zero' => [0], 'negative' => [-8]];
    }


    #[DataProvider('invalidCapacityProvider')]
    public function testRejectsACapacityWhichIsNotAPositiveMultipleOfEight(int $capacity): void
    {
        $this->assertRefusedBecause(
            sprintf(
                'Status List pool "default" is configured with a capacity of %d, which must be a ' .
                'positive multiple of 8.',
                $capacity,
            ),
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_CAPACITY => $capacity]),
        );
    }


    /**
     * @return array<string,array{string,mixed,string}>
     */
    public static function nonIntegerSettingProvider(): array
    {
        return [
            'bits as a string' => [StatusListPool::KEY_BITS, '2', 'string'],
            'capacity as a float' => [StatusListPool::KEY_CAPACITY, 1024.0, 'float'],
        ];
    }


    #[DataProvider('nonIntegerSettingProvider')]
    public function testRejectsANonIntegerValue(string $key, mixed $value, string $typeGiven): void
    {
        $this->assertRefusedBecause(
            sprintf('Status List pool "default" has a "%s" which is not an integer, %s given.', $key, $typeGiven),
            fn (): StatusListPool => $this->sut([$key => $value]),
        );
    }


    /**
     * The number of bits fixes the largest status a list can ever carry, and reconfiguring it later
     * can not retrofit lists which already exist. A pool which may suspend has to say so up front.
     */
    public function testRejectsAStatusWhichDoesNotFitTheConfiguredBits(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" allows the status Suspended (0x02), which can not be represented ' .
            'using 1 bit(s) per Referenced Token (largest is 0x01). Raise "bits" to at least 2, or ' .
            'remove the status.',
            fn (): StatusListPool => $this->sut([
                StatusListPool::KEY_BITS => 1,
                StatusListPool::KEY_ALLOWED_STATUSES => [StatusTypeEnum::Suspended],
            ]),
        );
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
        $this->assertFalse($pool->isStatusAllowed(StatusTypeEnum::Suspended));
        $this->assertSame('0,1', $pool->getAllowedStatusesAsString());
    }


    public function testAcceptsAStatusGivenAsItsRegisteredIntegerValue(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_BITS => 2,
            StatusListPool::KEY_ALLOWED_STATUSES => [1, 2],
        ]);

        $this->assertTrue($pool->isStatusAllowed(StatusTypeEnum::Invalid));
        $this->assertTrue($pool->isStatusAllowed(StatusTypeEnum::Suspended));
        $this->assertSame('0,1,2', $pool->getAllowedStatusesAsString());
    }


    /**
     * Casting a string to an integer turns every typo into 0, which is Valid, so a misspelt status
     * would silently configure the pool to allow nothing rather than being reported.
     */
    public function testRejectsAStatusGivenAsAString(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" allows a status which is not a ' . StatusTypeEnum::class .
            " case: 'invalid'.",
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_ALLOWED_STATUSES => ['invalid']]),
        );
    }


    public function testRejectsAnUnregisteredStatusValue(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" allows a status which is not a ' . StatusTypeEnum::class . ' case: 7.',
            fn (): StatusListPool => $this->sut([
                StatusListPool::KEY_BITS => 4,
                StatusListPool::KEY_ALLOWED_STATUSES => [7],
            ]),
        );
    }


    public function testRejectsAllowedStatusesWhichAreNotAnArray(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" has an "allowed_statuses" which is not an array.',
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_ALLOWED_STATUSES => 1]),
        );
    }


    public function testRejectsANonPositiveTtl(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" must have a positive "ttl".',
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_TTL => 'PT0S']),
        );
    }


    /**
     * Refused by its own rule, before the headroom rule gets to compare it with the token validity.
     */
    public function testRejectsANonPositiveRefreshInterval(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" must have a positive "refresh_interval".',
            fn (): StatusListPool => $this->sut([StatusListPool::KEY_REFRESH_INTERVAL => 'PT0S']),
        );
    }


    /**
     * Getting this the wrong way round leaves a recurring window in every cycle where the published
     * token has expired and its replacement has not been produced yet.
     */
    public function testRejectsARefreshIntervalWhichDoesNotFitInsideTheTokenValidity(): void
    {
        $this->assertRefusedBecause(
            'Status List pool "default" refreshes every 3600 second(s) but its tokens are only valid for ' .
            '3600 second(s). The refresh interval plus the 900 second safety margin must stay below the ' .
            'token validity, otherwise a published token expires before its replacement is produced. ' .
            'Raise "token_validity" or lower "refresh_interval".',
            fn (): StatusListPool => $this->sut([
                StatusListPool::KEY_REFRESH_INTERVAL => 'PT1H',
                StatusListPool::KEY_TOKEN_VALIDITY => 'PT1H',
            ]),
        );
    }


    public function testRejectsARefreshIntervalLeavingLessThanTheSafetyMargin(): void
    {
        // Ten minutes of headroom, where the safety margin asks for fifteen.
        $this->assertRefusedBecause(
            'Status List pool "default" refreshes every 3000 second(s) but its tokens are only valid for ' .
            '3600 second(s). The refresh interval plus the 900 second safety margin must stay below the ' .
            'token validity, otherwise a published token expires before its replacement is produced. ' .
            'Raise "token_validity" or lower "refresh_interval".',
            fn (): StatusListPool => $this->sut([
                StatusListPool::KEY_REFRESH_INTERVAL => 'PT50M',
                StatusListPool::KEY_TOKEN_VALIDITY => 'PT1H',
            ]),
        );
    }


    public function testAcceptsARefreshIntervalWithEnoughHeadroom(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_REFRESH_INTERVAL => 'PT30M',
            StatusListPool::KEY_TOKEN_VALIDITY => 'PT2H',
        ]);

        $this->assertSame(1800, $pool->getRefreshIntervalInSeconds());
    }


    /**
     * The wording after the colon is PHP's, so only the pool's part of the reason and the offending
     * value are pinned.
     */
    public function testRejectsAnUnparsableDuration(): void
    {
        try {
            $this->sut([StatusListPool::KEY_TTL => 'twelve hours']);
        } catch (ConfigurationError $e) {
            $this->assertStringStartsWith(
                'Status List pool "default" has a "ttl" which is not a valid duration: ',
                (string)$e->getReason(),
            );
            $this->assertStringContainsString('twelve hours', (string)$e->getReason());
            return;
        }

        $this->fail('A ConfigurationError was expected.');
    }


    /**
     * @return array<string,array{string,int}>
     */
    public static function durationKeyProvider(): array
    {
        return [
            'ttl' => [StatusListPool::KEY_TTL, 43200],
            'token validity' => [StatusListPool::KEY_TOKEN_VALIDITY, 604800],
            'refresh interval' => [StatusListPool::KEY_REFRESH_INTERVAL, 3600],
        ];
    }


    /**
     * A number of seconds is not accepted in place of a duration string, and the refusal names the key.
     */
    #[DataProvider('durationKeyProvider')]
    public function testRejectsADurationWhichIsNotAString(string $key, int $seconds): void
    {
        $this->assertRefusedBecause(
            sprintf('Status List pool "default" has a "%s" which is not a duration string, int given.', $key),
            fn (): StatusListPool => $this->sut([$key => $seconds]),
        );
    }


    public function testTellsWhichCredentialConfigurationsItServes(): void
    {
        $pool = $this->sut([
            StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['A', 'A', 'B', 'A'],
        ]);

        // Each once, and re-indexed as a list rather than with the gaps array_unique() leaves.
        $this->assertSame(['A', 'B'], $pool->getCredentialConfigurationIds());
        $this->assertTrue($pool->hasCredentialConfigurationId('A'));
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
            $seenRefresh = [];

            // Zones on both sides of UTC, one of which is deep in a daylight saving change window.
            foreach (['UTC', 'Europe/Zagreb', 'America/Santiago', 'Pacific/Chatham'] as $timezone) {
                date_default_timezone_set($timezone);

                $pool = $this->sut();
                $seenTtl[] = $pool->getTtlInSeconds();
                $seenValidity[] = $pool->getTokenValidityInSeconds();
                $seenRefresh[] = $pool->getRefreshIntervalInSeconds();
            }

            $this->assertSame([43200, 43200, 43200, 43200], $seenTtl);
            $this->assertSame([604800, 604800, 604800, 604800], $seenValidity);
            $this->assertSame([3600, 3600, 3600, 3600], $seenRefresh);
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
            // Valid alone, which fits the default bits, so that only the statuses differ.
            'allowed statuses' => [[StatusListPool::KEY_ALLOWED_STATUSES => []]],
            'key profile' => [[StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks]],
        ];
    }

    /**
     * @param array<array-key,mixed> $override
     */
    #[DataProvider('policyChangingOverrideProvider')]
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
     * A list records the identifier it was created under, so a changed identifier has to route new
     * credentials to a new list rather than onto one whose tokens still name the old issuer.
     */
    public function testPolicyFingerprintChangesWithTheIssuerIdentifier(): void
    {
        $didWeb = [StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb];

        $this->assertNotSame(
            $this->sut($didWeb, issuerIdentifier: self::DID_WEB)->getPolicyFingerprint(self::KEY_ID),
            $this->sut($didWeb, issuerIdentifier: 'did:web:other.example.org')
                ->getPolicyFingerprint(self::KEY_ID),
        );
    }


    /**
     * The identifier is part of the fingerprint only under the profile which uses it. Were it always
     * included, every deployment's pools would fingerprint differently the moment this option existed
     * and move onto fresh lists, splitting herds which had no reason to split.
     */
    #[DataProvider('profilesWhichDoNotUseTheIssuerIdentifierDataProvider')]
    public function testPolicyFingerprintIgnoresTheIssuerIdentifierUnderTheOtherProfiles(
        StatusListKeyProfileEnum $keyProfile,
    ): void {
        $config = [StatusListPool::KEY_KEY_PROFILE => $keyProfile];

        $this->assertSame(
            $this->sut($config)->getPolicyFingerprint(self::KEY_ID),
            $this->sut($config, issuerIdentifier: self::DID_WEB)->getPolicyFingerprint(self::KEY_ID),
        );
    }


    /**
     * @return array<string,array{\SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum}>
     */
    public static function profilesWhichDoNotUseTheIssuerIdentifierDataProvider(): array
    {
        return [
            'did:jwk' => [StatusListKeyProfileEnum::DidJwk],
            'jwks' => [StatusListKeyProfileEnum::Jwks],
        ];
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
