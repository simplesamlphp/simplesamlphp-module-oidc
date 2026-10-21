<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ValueAbstracts\ClientAttestationTrust;
use SimpleSAML\OpenID\X509\CertificateIdentityTypeEnum;

/**
 * The trust a client record keeps for its Client Attestations, read strictly: any member missing, empty, of the
 * wrong type or unknown is refused, never read as no trust.
 */
#[CoversClass(ClientAttestationTrust::class)]
class ClientAttestationTrustTest extends TestCase
{
    protected const string ANCHORS = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";


    /**
     * A digest as Certificate::getPublicKeySha256() writes it.
     */
    protected static function digest(string $of = 'issuing CA key'): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $of, true)), '+/', '-_'), '=');
    }


    /**
     * @return array<string,mixed>
     */
    protected static function stored(): array
    {
        return [
            'attester' => 'https://wallet-provider.example.org',
            'issuing_ca_public_key_sha256' => self::digest(),
            'attester_identity' => ['type' => 'san_uri', 'value' => 'https://wallet-provider.example.org'],
            'trust_anchors' => self::ANCHORS,
        ];
    }


    public function testReadsNoTrustFromAClientRecordWithoutOne(): void
    {
        $this->assertNull(ClientAttestationTrust::fromClientMetadata(null));
    }


    public function testReadsTheTrustAsStored(): void
    {
        $sut = ClientAttestationTrust::fromClientMetadata(self::stored());

        $this->assertInstanceOf(ClientAttestationTrust::class, $sut);
        $this->assertSame('https://wallet-provider.example.org', $sut->getAttester());
        $this->assertSame(self::digest(), $sut->getIssuingCaPublicKeySha256());
        $this->assertSame(CertificateIdentityTypeEnum::SubjectAlternativeNameUri, $sut->getAttesterIdentityType());
        $this->assertSame('https://wallet-provider.example.org', $sut->getAttesterIdentity());
        $this->assertSame(self::ANCHORS, $sut->getTrustAnchors());
        $this->assertSame(self::stored(), $sut->toClientMetadata());
    }


    /**
     * Every identity type the library can match is one a client can pin.
     */
    public function testReadsEveryIdentityType(): void
    {
        foreach (CertificateIdentityTypeEnum::cases() as $type) {
            $stored = self::stored();
            $stored['attester_identity'] = ['type' => $type->value, 'value' => 'CN=Wallet Provider,O=Example'];

            $this->assertSame(
                $type,
                ClientAttestationTrust::fromClientMetadata($stored)?->getAttesterIdentityType(),
                $type->value,
            );
        }
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function unreadableTrustProvider(): array
    {
        $without = static function (string $key): array {
            $stored = self::stored();
            unset($stored[$key]);
            return $stored;
        };
        $with = static fn(string $key, mixed $value): array => [...self::stored(), $key => $value];
        $withIdentity = static fn(array $identity): array => [...self::stored(), 'attester_identity' => $identity];

        return [
            'a string' => ['https://wallet-provider.example.org'],
            'a list' => [array_values(self::stored())],
            'an empty array' => [[]],
            'an unknown member' => [$with('attester_key', 'x')],
            'no attester' => [$without('attester')],
            'an empty attester' => [$with('attester', '')],
            'a blank attester' => [$with('attester', ' ')],
            'an attester which is not a string' => [$with('attester', ['https://wallet-provider.example.org'])],
            'no issuing CA digest' => [$without('issuing_ca_public_key_sha256')],
            'a digest of another length' => [$with('issuing_ca_public_key_sha256', substr(self::digest(), 1))],
            'a padded digest' => [$with('issuing_ca_public_key_sha256', self::digest() . '=')],
            'a base64 digest' => [$with('issuing_ca_public_key_sha256', '+' . substr(self::digest(), 1))],
            'a digest no encoder writes' => [
                $with('issuing_ca_public_key_sha256', substr(self::digest(), 0, 42) . 'B'),
            ],
            'a hex digest' => [$with('issuing_ca_public_key_sha256', hash('sha256', 'issuing CA key'))],
            'no identity' => [$without('attester_identity')],
            'an identity which is a string' => [$with('attester_identity', 'https://wallet-provider.example.org')],
            'an identity which is a list' => [$withIdentity(['san_uri', 'https://wallet-provider.example.org'])],
            'an identity without a type' => [$withIdentity(['value' => 'https://wallet-provider.example.org'])],
            'an identity of an unknown type' => [
                $withIdentity(['type' => 'email', 'value' => 'wallet@example.org']),
            ],
            'an identity type in another case' => [
                $withIdentity(['type' => 'SAN_URI', 'value' => 'https://wallet-provider.example.org']),
            ],
            'an identity without a value' => [$withIdentity(['type' => 'san_uri'])],
            'an identity with an empty value' => [$withIdentity(['type' => 'san_uri', 'value' => ''])],
            'an identity with an unknown member' => [
                $withIdentity(['type' => 'san_uri', 'value' => 'https://w.example.org', 'issuer' => 'x']),
            ],
            'no trust anchors' => [$without('trust_anchors')],
            'empty trust anchors' => [$with('trust_anchors', '')],
            'trust anchors which are a list' => [$with('trust_anchors', [self::ANCHORS])],
        ];
    }


    #[DataProvider('unreadableTrustProvider')]
    public function testRefusesATrustItCanNotRead(mixed $stored): void
    {
        $this->expectException(OidcException::class);

        ClientAttestationTrust::fromClientMetadata($stored);
    }
}
