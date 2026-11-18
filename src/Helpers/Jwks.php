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


    /**
     * What keeps the value from being a JWK Set a client may be registered with, or null when nothing does: a JSON
     * object whose `keys` member is a non-empty array (a JSON array, so a list) of JWKs (RFC 7517 section 5), each a
     * JSON object naming its key type, `kty` (section 4.1). The JOSE library builds every key of a set it is given
     * and refuses the whole set for one without `kty`, so a set with such a key would fail client authentication
     * and Request Object verification however good its other keys. Shared by the client administration form and
     * Dynamic Client Registration, so that neither stores a set which the other refuses.
     *
     * Each answer names the first thing wrong, in words fit for the form's error list.
     */
    public function keySetProblem(mixed $jwks): ?string
    {
        if (!is_array($jwks)) {
            return 'Invalid JWKS format';
        }

        if (!array_key_exists('keys', $jwks)) {
            return 'No keys property in JWKS';
        }

        $keys = $jwks['keys'];

        if (!is_array($keys) || !array_is_list($keys)) {
            return 'Keys property in JWKS is not a list';
        }

        if ($keys === []) {
            return 'Empty keys in JWKS';
        }

        foreach ($keys as $key) {
            if (!is_array($key) || !is_string($key['kty'] ?? null) || $key['kty'] === '') {
                return 'Key in JWKS is not a JSON object with a key type (kty)';
            }
        }

        return null;
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
