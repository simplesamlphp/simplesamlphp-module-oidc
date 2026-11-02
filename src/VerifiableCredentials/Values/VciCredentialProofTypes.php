<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * The key proof types a credential configuration takes, and for each what it requires of key attestations: its
 * entry under ModuleConfig::OPTION_VCI_CREDENTIAL_PROOF_TYPES, or `jwt` alone without key attestations for a
 * configuration which has none (jwtOnly()).
 *
 * An `attestation` proof is a key attestation (OpenID4VCI 1.0 Appendix F.3), so that proof type requires one whether
 * or not it states requirements; a `jwt` proof requires one in its `key_attestation` header only where the
 * configuration says so.
 */
class VciCredentialProofTypes
{
    // phpcs:disable Generic.Files.LineLength.TooLong
    /**
     * @param array<string,?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements> $proofTypes
     * At least one: each proof type offered (a VciProofTypeEnum value), in the order it is published, with what it
     * requires of key attestations, or null for no `key_attestations_required`.
     */
    public function __construct(
        protected readonly array $proofTypes,
    ) {
    }
    // phpcs:enable Generic.Files.LineLength.TooLong


    /**
     * What a configuration without an entry of its own takes: `jwt` proofs, without key attestations.
     */
    public static function jwtOnly(): self
    {
        return new self([VciProofTypeEnum::Jwt->value => null]);
    }


    public function offers(VciProofTypeEnum $proofType): bool
    {
        return array_key_exists($proofType->value, $this->proofTypes);
    }


    /**
     * @return non-empty-list<\SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum>
     */
    public function getOffered(): array
    {
        /** @var non-empty-list<\SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum> $offered */
        $offered = array_map(
            VciProofTypeEnum::from(...),
            array_keys($this->proofTypes),
        );

        return $offered;
    }


    /**
     * Whether a proof of this type has to be, or carry, a key attestation: always for `attestation`, for `jwt` where
     * the configuration states `key_attestations_required`. False for a proof type not offered.
     */
    public function requiresKeyAttestation(VciProofTypeEnum $proofType): bool
    {
        if (!$this->offers($proofType)) {
            return false;
        }

        return $proofType === VciProofTypeEnum::Attestation || $this->proofTypes[$proofType->value] !== null;
    }


    /**
     * What the proof type requires of the levels a key attestation states, or null when nothing (no
     * `key_attestations_required`, or a proof type not offered).
     */
    public function getKeyAttestationRequirementsFor(VciProofTypeEnum $proofType): ?VciKeyAttestationRequirements
    {
        return $this->proofTypes[$proofType->value] ?? null;
    }


    /**
     * Whether any proof type offered requires a key attestation, for which this issuer needs the trust anchors of
     * ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME.
     */
    public function requiresAnyKeyAttestation(): bool
    {
        foreach ($this->getOffered() as $proofType) {
            if ($this->requiresKeyAttestation($proofType)) {
                return true;
            }
        }

        return false;
    }


    /**
     * The `proof_types_supported` object of the configuration's metadata (OpenID4VCI 1.0 section 12.2.4).
     *
     * @param string[] $proofSigningAlgorithms The `proof_signing_alg_values_supported` of every proof type: for
     * `attestation` the algorithms of the key attestation (Appendix F.3), for `jwt` those of the proof and of a key
     * attestation it carries (F.1). Published as a JSON array whatever their keys.
     * @return array<string,array<string,mixed>> By proof type, one entry for each offered.
     */
    public function toMetadata(array $proofSigningAlgorithms): array
    {
        $metadata = [];
        $proofSigningAlgorithms = array_values($proofSigningAlgorithms);

        foreach ($this->proofTypes as $proofType => $requirements) {
            $metadata[$proofType] = [ClaimsEnum::ProofSigningAlgValuesSupported->value => $proofSigningAlgorithms];

            if ($requirements !== null) {
                $metadata[$proofType][ClaimsEnum::KeyAttestationsRequired->value] = $requirements->toMetadata();
            }
        }

        return $metadata;
    }
}
