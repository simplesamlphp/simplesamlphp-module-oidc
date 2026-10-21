<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\OpenID\X509\CertificateIdentityTypeEnum;

/**
 * Whom the Client Attestations of a client authenticating with `attest_jwt_client_auth` are trusted from
 * (draft-ietf-oauth-attestation-based-client-auth-07 section 9, check 5), kept on the client's record: the
 * attester's `iss`, the trust anchors its certificate chain has to validate against, the issuing CA its
 * certificate has to be issued by, pinned by the SHA-256 digest of that CA's SubjectPublicKeyInfo, and the
 * attester's identity in its certificate as a typed value.
 *
 * The issuing CA is pinned because the identity alone does not tell providers apart: RFC 5280 section 4.1.2.6
 * has a subject name unique only among the certificates of one CA, and any provider certified under a trusted root
 * could otherwise sign for this client by asserting its attester's `iss`, which draft 07 binds to nothing. Pinned
 * by its key, a renewal of the issuing CA's certificate with the same key, or of the attester's certificate, needs
 * no change here.
 */
class ClientAttestationTrust
{
    final public const string KEY_ATTESTER = 'attester';

    final public const string KEY_ISSUING_CA_PUBLIC_KEY_SHA256 = 'issuing_ca_public_key_sha256';

    final public const string KEY_ATTESTER_IDENTITY = 'attester_identity';

    final public const string KEY_IDENTITY_TYPE = 'type';

    final public const string KEY_IDENTITY_VALUE = 'value';

    final public const string KEY_TRUST_ANCHORS = 'trust_anchors';

    /**
     * A SHA-256 digest is 32 octets, 43 characters in base64url without padding, as
     * \SimpleSAML\OpenID\X509\Certificate::getPublicKeySha256() writes it. The last character carries the last four
     * bits of the digest and two zero bits, so only sixteen characters can end it; a digest written otherwise is not
     * one that function writes, and would never match.
     */
    protected const string PUBLIC_KEY_SHA256_PATTERN = '/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]\z/';


    /**
     * @param non-empty-string $attester
     * @param non-empty-string $issuingCaPublicKeySha256
     * @param non-empty-string $attesterIdentity
     * @param non-empty-string $trustAnchors
     */
    public function __construct(
        protected readonly string $attester,
        protected readonly string $issuingCaPublicKeySha256,
        protected readonly CertificateIdentityTypeEnum $attesterIdentityType,
        protected readonly string $attesterIdentity,
        protected readonly string $trustAnchors,
    ) {
    }


    /**
     * The trust as a client record keeps it:
     * `['attester' => iss, 'issuing_ca_public_key_sha256' => digest, 'attester_identity' => ['type' => type,
     * 'value' => value], 'trust_anchors' => PEM]`, or null for a client which has none.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException When the stored value is not that, a member being
     * missing, of the wrong type, empty or unknown. It is never read as "no trust", which would turn a client
     * somebody set up for attestation into one which can not tell why it fails, nor with a member left out.
     */
    public static function fromClientMetadata(mixed $value): ?self
    {
        if (is_null($value)) {
            return null;
        }

        if (!is_array($value) || array_is_list($value)) {
            throw new OidcException('The client attestation trust must be an object.');
        }

        $knownKeys = [
            self::KEY_ATTESTER,
            self::KEY_ISSUING_CA_PUBLIC_KEY_SHA256,
            self::KEY_ATTESTER_IDENTITY,
            self::KEY_TRUST_ANCHORS,
        ];
        $unknownKeys = array_diff(array_map(strval(...), array_keys($value)), $knownKeys);
        if ($unknownKeys !== []) {
            throw new OidcException(
                'The client attestation trust has unknown members: ' . implode(', ', $unknownKeys) . '.',
            );
        }

        $attester = self::nonEmptyString($value, self::KEY_ATTESTER);

        $issuingCaPublicKeySha256 = self::nonEmptyString($value, self::KEY_ISSUING_CA_PUBLIC_KEY_SHA256);
        if (preg_match(self::PUBLIC_KEY_SHA256_PATTERN, $issuingCaPublicKeySha256) !== 1) {
            throw new OidcException(
                'The issuing CA public key digest of the client attestation trust is not a base64url encoded ' .
                'SHA-256 digest.',
            );
        }

        $identity = $value[self::KEY_ATTESTER_IDENTITY] ?? null;
        if (!is_array($identity) || array_is_list($identity)) {
            throw new OidcException('The attester identity of the client attestation trust must be an object.');
        }

        $unknownIdentityKeys = array_diff(
            array_map(strval(...), array_keys($identity)),
            [self::KEY_IDENTITY_TYPE, self::KEY_IDENTITY_VALUE],
        );
        if ($unknownIdentityKeys !== []) {
            throw new OidcException(
                'The attester identity of the client attestation trust has unknown members: ' .
                implode(', ', $unknownIdentityKeys) . '.',
            );
        }

        $identityType = CertificateIdentityTypeEnum::tryFrom(self::nonEmptyString($identity, self::KEY_IDENTITY_TYPE))
        ?? throw new OidcException(
            sprintf(
                'The attester identity type of the client attestation trust must be one of: %s.',
                implode(', ', array_map(
                    static fn(CertificateIdentityTypeEnum $type): string => $type->value,
                    CertificateIdentityTypeEnum::cases(),
                )),
            ),
        );

        return new self(
            $attester,
            $issuingCaPublicKeySha256,
            $identityType,
            self::nonEmptyString($identity, self::KEY_IDENTITY_VALUE),
            self::nonEmptyString($value, self::KEY_TRUST_ANCHORS),
        );
    }


    /**
     * @param array<array-key,mixed> $value
     * @return non-empty-string
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected static function nonEmptyString(array $value, string $key): string
    {
        $member = $value[$key] ?? null;

        if (!is_string($member) || $member === '' || trim($member) === '') {
            throw new OidcException(
                sprintf('The member "%s" of the client attestation trust must be a non-empty string.', $key),
            );
        }

        return $member;
    }


    /**
     * The trust as fromClientMetadata() reads it.
     *
     * @return array{attester: non-empty-string, issuing_ca_public_key_sha256: non-empty-string,
     * attester_identity: array{type: string, value: non-empty-string}, trust_anchors: non-empty-string}
     */
    public function toClientMetadata(): array
    {
        return [
            self::KEY_ATTESTER => $this->attester,
            self::KEY_ISSUING_CA_PUBLIC_KEY_SHA256 => $this->issuingCaPublicKeySha256,
            self::KEY_ATTESTER_IDENTITY => [
                self::KEY_IDENTITY_TYPE => $this->attesterIdentityType->value,
                self::KEY_IDENTITY_VALUE => $this->attesterIdentity,
            ],
            self::KEY_TRUST_ANCHORS => $this->trustAnchors,
        ];
    }


    /**
     * The `iss` of the attestations, compared exactly (draft 07 section 5.1: Simple String Comparison).
     *
     * @return non-empty-string
     */
    public function getAttester(): string
    {
        return $this->attester;
    }


    /**
     * @return non-empty-string
     */
    public function getIssuingCaPublicKeySha256(): string
    {
        return $this->issuingCaPublicKeySha256;
    }


    public function getAttesterIdentityType(): CertificateIdentityTypeEnum
    {
        return $this->attesterIdentityType;
    }


    /**
     * @return non-empty-string
     */
    public function getAttesterIdentity(): string
    {
        return $this->attesterIdentity;
    }


    /**
     * The trust anchors, as PEM: one or more self-signed CA certificates.
     *
     * @return non-empty-string
     */
    public function getTrustAnchors(): string
    {
        return $this->trustAnchors;
    }
}
