<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;

/**
 * Every column of the row holds a value no other column holds, so that a column read into the wrong field shows.
 * The column names are those the migration creates.
 */
#[CoversClass(CredentialOfferRecord::class)]
class CredentialOfferRecordTest extends TestCase
{
    protected const string OFFER_ID = '4c1e9b07d2a85f36e0b7c94a1d6f23e85b0a7c4d9e12f6b38a5c0e7d94b1f26a';


    /**
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    protected function row(array $overrides = []): array
    {
        return array_merge([
            'id' => self::OFFER_ID,
            'owner' => 'HR system',
            'credential_configuration_ids' => '["employee_card","library_card"]',
            'grant_type' => 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'created_at' => '2026-11-11 10:00:01',
            'redeemable_until' => '2026-11-11 10:10:02',
            'retained_until' => '2026-11-11 11:15:03',
            'redeemed_at' => '2026-11-11 10:05:04',
            'withdrawn_at' => '2026-11-11 10:20:05',
        ], $overrides);
    }


    protected function utc(?DateTimeImmutable $moment): ?string
    {
        return $moment?->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }


    public function testReadsEveryColumnOfARowIntoItsOwnField(): void
    {
        $offer = CredentialOfferRecord::fromRow($this->row());

        $this->assertSame(self::OFFER_ID, $offer->getId());
        $this->assertSame('HR system', $offer->getOwner());
        $this->assertSame(['employee_card', 'library_card'], $offer->getCredentialConfigurationIds());
        $this->assertSame('urn:ietf:params:oauth:grant-type:pre-authorized_code', $offer->getGrantType());
        $this->assertSame('2026-11-11 10:00:01', $this->utc($offer->getCreatedAt()));
        $this->assertSame('2026-11-11 10:10:02', $this->utc($offer->getRedeemableUntil()));
        $this->assertSame('2026-11-11 11:15:03', $this->utc($offer->getRetainedUntil()));
        $this->assertSame('2026-11-11 10:05:04', $this->utc($offer->getRedeemedAt()));
        $this->assertSame('2026-11-11 10:20:05', $this->utc($offer->getWithdrawnAt()));
    }


    /**
     * Stored moments are UTC wall clocks, whatever zone the server runs in.
     */
    public function testReadsMomentsAsUtcWhateverTheServersZone(): void
    {
        $zone = date_default_timezone_get();
        date_default_timezone_set('America/New_York');

        try {
            $offer = CredentialOfferRecord::fromRow($this->row());
        } finally {
            date_default_timezone_set($zone);
        }

        $this->assertSame(
            (new DateTimeImmutable('2026-11-11 10:00:01', new DateTimeZone('UTC')))->getTimestamp(),
            $offer->getCreatedAt()->getTimestamp(),
        );
    }


    public function testReadsAnOfferNotYetRedeemedNorWithdrawnAndOwnedByNoOne(): void
    {
        $offer = CredentialOfferRecord::fromRow(
            $this->row(['owner' => null, 'redeemed_at' => null, 'withdrawn_at' => null]),
        );

        $this->assertNull($offer->getOwner());
        $this->assertNull($offer->getRedeemedAt());
        $this->assertNull($offer->getWithdrawnAt());
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function malformedRowProvider(): array
    {
        return [
            'no id' => [['id' => null]],
            'no grant type' => [['grant_type' => null]],
            'no creation moment' => [['created_at' => null]],
            'no end of redeemability' => [['redeemable_until' => null]],
            'no retention' => [['retained_until' => null]],
            'a retention which is no moment' => [['retained_until' => 'soon']],
            'a redemption which is no moment' => [['redeemed_at' => 'yesterday-ish']],
            // The parser would read a blank as the current time.
            'a blank creation moment' => [['created_at' => '']],
            'a blank retention' => [['retained_until' => '  ']],
            'a blank redemption' => [['redeemed_at' => '']],
            'a blank withdrawal' => [['withdrawn_at' => ' ']],
            'no configurations' => [['credential_configuration_ids' => null]],
            'configurations which are not JSON' => [['credential_configuration_ids' => '[employee_card']],
            'configurations which are not a list' => [['credential_configuration_ids' => '{"a":"employee_card"}']],
            'a configuration which is not a string' => [['credential_configuration_ids' => '["employee_card",7]']],
            'configurations which are a string' => [['credential_configuration_ids' => '"employee_card"']],
        ];
    }


    /**
     * @param array<string,mixed> $overrides
     */
    #[DataProvider('malformedRowProvider')]
    public function testRefusesARowWhichHoldsNoOfferRecord(array $overrides): void
    {
        $this->expectException(RuntimeException::class);

        CredentialOfferRecord::fromRow($this->row($overrides));
    }


    /**
     * @return array<string,array{?string,string,bool}>
     */
    public static function ownershipProvider(): array
    {
        return [
            'the same principal' => ['HR system', 'HR system', true],
            'another principal' => ['HR system', 'Library system', false],
            // MySQL's default collations would take these for the owner; the comparison is not theirs to make.
            'another case' => ['HR system', 'hr system', false],
            'a trailing space' => ['HR system', 'HR system ', false],
            'a prefix of the owner' => ['HR system', 'HR', false],
            'a token fingerprint' => ['token:0123456789abcdef', 'token:0123456789abcdef', true],
            'an administrator\'s offer' => [null, 'HR system', false],
            'an administrator\'s offer, asked as the administrator principal' => [null, 'simplesamlphp-admin', false],
            'an administrator\'s offer, asked by an empty principal' => [null, '', false],
        ];
    }


    #[DataProvider('ownershipProvider')]
    public function testIsOwnedOnlyByThePrincipalWhichMadeIt(?string $owner, string $principal, bool $expected): void
    {
        $offer = CredentialOfferRecord::fromRow($this->row(['owner' => $owner]));

        $this->assertSame($expected, $offer->isOwnedBy($principal));
    }
}
