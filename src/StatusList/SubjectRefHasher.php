<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use Defuse\Crypto\Key;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Turns a user identifier into the opaque `subject_ref` recorded against a Status List entry.
 *
 * Storing anything about issued credentials is a change in the module's privacy posture, so what gets
 * stored is kept to the minimum which makes the administrative surface usable: enough to group a
 * subject's credentials together, not enough to recover who they are from the database alone.
 *
 * This is a *keyed* hash, which is the whole point. An email address or an eduPersonPrincipalName has
 * far too little entropy to survive a plain hash, salted or not -- anyone holding the database could
 * confirm a guess by hashing it. Without the key, which never goes into the database, the stored value
 * says nothing.
 *
 * The key is derived from the module's encryption key (which itself falls back to the SimpleSAMLphp
 * secret salt) through HKDF with a fixed info string, so there is no additional secret for an operator
 * to generate, store or lose. Rotating the encryption key changes every `subject_ref`, which is
 * acceptable: these values are an administrative convenience for grouping, never an identifier
 * anything depends on.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\SubjectRefHasherTest
 */
class SubjectRefHasher
{
    /**
     * Domain separation for the derived key, so that the same encryption key used elsewhere in the
     * module can never produce the same bytes this does.
     */
    protected const string HKDF_INFO = 'simplesamlphp-module-oidc:status-list:subject-ref:v1';

    protected const string HASH_ALGORITHM = 'sha256';

    /** Length of the derived key, matching the output size of the hash it keys. */
    protected const int DERIVED_KEY_BYTES = 32;


    /** Derived once per request, since every allocation in a batch issuance needs it. */
    protected ?string $derivedKey = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }


    /**
     * @return string 64 lowercase hex characters, sized for the CHAR(64) column it is stored in.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function hash(string $userIdentifier): string
    {
        return hash_hmac(self::HASH_ALGORITHM, $userIdentifier, $this->deriveKey());
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
                'Unable to derive the Status List subject reference key: neither a module encryption ' .
                'key nor a SimpleSAMLphp secret salt is set.',
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
