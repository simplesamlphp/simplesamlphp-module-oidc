<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services\Api;

use Defuse\Crypto\Key;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * Works out who an API token stands for, so that a change it makes can be attributed.
 *
 * API tokens have never had an identity in this module: the configuration maps a token straight to a
 * set of scopes, so the only thing distinguishing one caller from another was the secret itself. That
 * is fine while the API only reads or creates things which carry their own record, and not fine for an
 * endpoint whose whole purpose is to record who withdrew a credential.
 *
 * A configured name is used when there is one. Failing that the token is reduced to a short fingerprint
 * so that separate callers stay separate in the trail, which is the least an audit has to do. The
 * fingerprint is keyed, derived through HKDF from the module's encryption key exactly as
 * {@see \SimpleSAML\Module\oidc\StatusList\SubjectRefHasher} derives its own, and for the same reason:
 * an unkeyed hash of a token an operator chose badly could be confirmed by guessing, which would turn
 * the audit trail into an oracle for the secret it was meant to keep out.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Services\Api\ApiTokenPrincipalResolverTest
 */
class ApiTokenPrincipalResolver
{
    /**
     * Domain separation for the derived key, so that no other keyed value in the module can ever be
     * the same bytes as one of these.
     */
    protected const string HKDF_INFO = 'simplesamlphp-module-oidc:api-token-principal:v1';

    protected const string HASH_ALGORITHM = 'sha256';

    protected const int DERIVED_KEY_BYTES = 32;

    /**
     * Hex characters of fingerprint kept.
     *
     * Enough that two configured tokens colliding is not a practical concern, short enough to read in
     * a table. It is a label, not a credential.
     */
    protected const int FINGERPRINT_LENGTH = 16;

    /** Marks a fingerprint as such, so it is never mistaken for a name someone chose. */
    protected const string FINGERPRINT_PREFIX = 'token:';


    protected ?string $derivedKey = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * @return string Never the token, and never empty.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function resolve(string $token): string
    {
        $name = $this->moduleConfig->getApiTokenName($token);

        // The invariant is that no bearer secret this module knows about can reach the value returned
        // here, which is logged and written to the audit trail. Nothing stops an operator writing one
        // into a name: "HR system (abc123)" reads like a helpful label and hands the secret to
        // everyone who can read the table.
        //
        // Checked against every configured token rather than only the one being resolved, because a
        // name is just as dangerous when the secret buried in it belongs to a different token -- and
        // that one would authenticate perfectly well while leaking somebody else's.
        //
        // Ignored rather than refused: this is the operator's mistake to fix, and refusing would take
        // revocation away until they did, which is not a trade worth making for a naming slip.
        if (is_string($name) && $this->carriesAToken($name)) {
            $this->loggerService->warning(
                'An API token is named with something containing an API token, which would put a ' .
                'bearer secret in the status change audit trail. The name is being ignored; give the ' .
                'token a name which does not carry one.',
            );

            $name = null;
        }

        return $name ?? $this->fingerprint($token);
    }


    /**
     * Whether a name has any configured API token buried in it.
     *
     * A token short enough for a name to contain it by chance is already far too weak to be worth
     * protecting, and being wrong here costs a fingerprint in place of a label.
     */
    protected function carriesAToken(string $name): bool
    {
        foreach (array_keys($this->moduleConfig->getApiTokens() ?? []) as $configuredToken) {
            if (is_string($configuredToken) && $configuredToken !== '' && str_contains($name, $configuredToken)) {
                return true;
            }
        }

        return false;
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function fingerprint(string $token): string
    {
        return self::FINGERPRINT_PREFIX . substr(
            hash_hmac(self::HASH_ALGORITHM, $token, $this->deriveKey()),
            0,
            self::FINGERPRINT_LENGTH,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function deriveKey(): string
    {
        if (is_string($this->derivedKey)) {
            return $this->derivedKey;
        }

        $encryptionKey = $this->moduleConfig->getEncryptionKey();

        $inputKeyMaterial = $encryptionKey instanceof Key ?
        $encryptionKey->getRawBytes() :
        $encryptionKey;

        if ($inputKeyMaterial === '') {
            throw new ConfigurationError(
                'Unable to derive the API token fingerprint key: neither a module encryption key nor a ' .
                'SimpleSAMLphp secret salt is set. Naming the token in the API token configuration ' .
                'avoids needing one at all.',
            );
        }

        return $this->derivedKey = hash_hkdf(
            self::HASH_ALGORITHM,
            $inputKeyMaterial,
            self::DERIVED_KEY_BYTES,
            self::HKDF_INFO,
        );
    }
}
