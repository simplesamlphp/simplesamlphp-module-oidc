<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers\Jwks;

#[CoversClass(Jwks::class)]
class JwksTest extends TestCase
{
    protected const array EC_JWK = ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y'];

    protected const array OKP_JWK = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'x'];


    protected function sut(): Jwks
    {
        return new Jwks();
    }


    /**
     * A public RSA key whose modulus has the given length: its most significant bit followed by ones. Only the length
     * is read.
     *
     * @return array<string,string>
     */
    protected static function rsaJwk(int $modulusBits, string $keyId): array
    {
        $octets = intdiv($modulusBits + 7, 8);
        $modulus = chr(1 << ($modulusBits - ($octets - 1) * 8 - 1)) . str_repeat("\xFF", $octets - 1);

        return [
            'kty' => 'RSA',
            'kid' => $keyId,
            'n' => rtrim(strtr(base64_encode($modulus), '+/', '-_'), '='),
            'e' => 'AQAB',
        ];
    }


    /**
     * The RSA keys shorter than 2048 bits go (FAPI 2.0 section 5.4.1), counted in bits rather than octets; RSA keys
     * of 2048 bits or more, keys of other types and the other members of the set stay, the keys in their order.
     */
    public function testLeavesOutTheRsaKeysShorterThan2048Bits(): void
    {
        $this->assertSame(
            [
                'keys' => [self::EC_JWK, self::rsaJwk(2048, 'rsa-2048'), self::OKP_JWK, self::rsaJwk(4096, 'rsa-4096')],
                'member' => 'kept',
            ],
            $this->sut()->withoutShortRsaKeys([
                'keys' => [
                    self::rsaJwk(1024, 'rsa-1024'),
                    self::EC_JWK,
                    self::rsaJwk(2047, 'rsa-2047'),
                    self::rsaJwk(2048, 'rsa-2048'),
                    self::OKP_JWK,
                    self::rsaJwk(4096, 'rsa-4096'),
                ],
                'member' => 'kept',
            ]),
        );
    }


    public function testLeavesAKeySetWithoutShortRsaKeysAsItIs(): void
    {
        $jwks = ['keys' => [self::rsaJwk(2048, 'rsa-2048'), self::EC_JWK]];

        $this->assertSame($jwks, $this->sut()->withoutShortRsaKeys($jwks));
    }


    /**
     * An RSA key whose modulus can not be read verifies nothing, and goes too.
     */
    public function testLeavesOutAnRsaKeyWhoseModulusCanNotBeRead(): void
    {
        $this->assertSame(
            ['keys' => [self::rsaJwk(2048, 'rsa-2048')]],
            $this->sut()->withoutShortRsaKeys([
                'keys' => [
                    ['kty' => 'RSA', 'e' => 'AQAB'],
                    ['kty' => 'RSA', 'n' => '!!', 'e' => 'AQAB'],
                    ['kty' => 'RSA', 'n' => 65537, 'e' => 'AQAB'],
                    ['kty' => 'RSA', 'n' => 'AAAA', 'e' => 'AQAB'],
                    self::rsaJwk(2048, 'rsa-2048'),
                ],
            ]),
        );
    }


    /**
     * What is not a key set, or not a key, is left as it is, for the verification to refuse.
     */
    public function testLeavesWhatIsNotAKeyAsItIs(): void
    {
        $this->assertSame([], $this->sut()->withoutShortRsaKeys([]));
        $this->assertSame(['keys' => 'none'], $this->sut()->withoutShortRsaKeys(['keys' => 'none']));
        $this->assertSame(
            ['keys' => ['not a key', ['kid' => 'no type']]],
            $this->sut()->withoutShortRsaKeys(
                ['keys' => ['not a key', self::rsaJwk(1024, 'rsa-1024'), ['kid' => 'no type']]],
            ),
        );
    }
}
