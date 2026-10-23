<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use SimpleSAML\OpenID\Helpers\Jwk;
use Throwable;

class Jwks
{
    public function __construct(
        protected readonly Jwk $jwk = new Jwk(),
    ) {
    }


    /**
     * The key set without its RSA keys shorter than FAPI 2.0 lets sign with (section 5.4.1: 2048 bits), so that a
     * signature one of them made does not verify with it. An RSA key whose modulus can not be read goes too: it
     * verifies nothing. Every other key, and every other member of the set, is kept as it is.
     *
     * @param array<array-key,mixed> $jwks A JWK Set (RFC 7517 section 5), such as a client's (JwksResolver).
     * @return array<array-key,mixed>
     */
    public function withoutShortRsaKeys(array $jwks): array
    {
        $keys = $jwks['keys'] ?? null;

        if (!is_array($keys)) {
            return $jwks;
        }

        $jwks['keys'] = array_values(array_filter($keys, $this->isNotAShortRsaKey(...)));

        return $jwks;
    }


    protected function isNotAShortRsaKey(mixed $key): bool
    {
        if (!is_array($key) || ($key['kty'] ?? null) !== 'RSA') {
            return true;
        }

        try {
            /** @var array<string,mixed> $key */
            return $this->jwk->getRsaModulusBitLength($key) >= Jwk::MIN_RSA_MODULUS_BITS;
        } catch (Throwable) {
            return false;
        }
    }
}
