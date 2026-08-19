<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

/**
 * Which key a Status List Token is signed with.
 *
 * Two different questions, deliberately kept apart. Creating a list asks for the *current* key, which
 * is the same one credentials are being signed with, so that the profile saying the two are the same
 * key actually holds. Publishing an existing list asks for *the key that list was created with*, which
 * may no longer be the current one.
 *
 * That second question is why private keys have to be retained while any list they signed is still
 * served. When the key is gone, publication fails, and it must fail loudly rather than fall back to
 * the current key: a token signed with a key the credential's holder never bound to is not one they
 * can verify, and quietly producing one would look like success.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListKeyResolverTest
 */
class StatusListKeyResolver
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * The key newly created lists are bound to.
     *
     * Deliberately the same active Verifiable Credential Issuance key pair the credential issuance path
     * signs with, asked for through the same accessor. If the two ever diverge, a credential would be
     * signed with one key while the Status List Token its holder is told to check is signed with another.
     *
     * @see \SimpleSAML\Module\oidc\ModuleConfig::getActiveVciSignatureKeyPair()
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function getCurrent(): SignatureKeyPair
    {
        try {
            return $this->moduleConfig->getActiveVciSignatureKeyPair();
        } catch (\Throwable $throwable) {
            throw new StatusListException(
                'No Verifiable Credential Issuance signature key pair is configured, so Status Lists ' .
                'can not be signed: ' . $throwable->getMessage(),
                (int)$throwable->getCode(),
                $throwable,
            );
        }
    }

    /**
     * The identifier stored against a list, being either the configured key ID or, when none was
     * configured, the thumbprint derived from the key itself. It has to be exactly what the key pair
     * bag indexes by, otherwise a list could never find its key again.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    public function getCurrentKeyId(): string
    {
        return $this->getCurrent()->getKeyPair()->getKeyId();
    }

    /**
     * The key a list was created with.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When that key is no longer
     * configured. The caller must treat this as a failure to publish rather than reach for another key.
     */
    public function getByKeyId(string $keyId): SignatureKeyPair
    {
        $signatureKeyPair = $this->moduleConfig->getVciSignatureKeyPairBag()->getByKeyId($keyId);

        if ($signatureKeyPair === null) {
            throw new StatusListException(
                sprintf(
                    'Status List was signed with the key "%s", which is no longer configured. Private ' .
                    'keys must be retained for as long as any Status List they signed is still being ' .
                    'served, otherwise the credentials pointing at that list can not be verified.',
                    $keyId,
                ),
            );
        }

        return $signatureKeyPair;
    }
}
