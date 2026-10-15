<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;

/**
 * Where the claim paths of a credential configuration (OpenID4VCI 1.0 Appendix B.2) put their claims in a credential
 * this issuer issues, and which of those claims the issuer writes itself rather than the attribute mapping. The
 * Credential Endpoint writes mapped attributes and judges mandatory claims by it, and ModuleConfig refuses a
 * configuration with a mandatory claim nothing writes by it, so the two can not locate a claim differently.
 */
class CredentialClaimLocator
{
    /**
     * The claims the Credential Endpoint writes into a credential of each format itself, located as the claim paths
     * of the format are (locate()): members of the `dc+sd-jwt` payload; members of the `vc+sd-jwt` payload, which is
     * the data model credential with the JWT claims beside it; and members of the `jwt_vc_json` credential, its `vc`
     * claim, since a claims path pointer points into the credential (Appendix C.1) and not into the JWT around it.
     * A `vc+sd-jwt` claim path is rooted under `credentialSubject` unless its parent path names it, as a mapped
     * attribute's is (claimPathInCredential()), so of that format's members an ordinary path reaches only
     * `credentialSubject.id`; the rest are listed because they are what the issuer writes.
     *
     * Each is listed whether or not this deployment writes it: `exp` and `expirationDate` or `validUntil` only with a
     * credential lifetime, `status` only with Status Lists, `cnf` or the `dc+sd-jwt` `sub` by holder binding, `fed`
     * and `termsOfUse` only with OpenID Federation. A mandatory claim the issuer may write is its own to include,
     * so none of them is held against a configuration. `credentialSubject` itself is not listed, only the `id` the
     * issuer writes in it: the rest of it is the attribute mapping's to write.
     *
     * @var array<string,list<list<string>>>
     */
    public const array ISSUER_WRITTEN_CLAIM_PATHS = [
        CredentialFormatIdentifiersEnum::DcSdJwt->value => [
            [ClaimsEnum::Iss->value],
            [ClaimsEnum::Iat->value],
            [ClaimsEnum::Nbf->value],
            [ClaimsEnum::Sub->value],
            [ClaimsEnum::Jti->value],
            [ClaimsEnum::Vct->value],
            [ClaimsEnum::Status->value],
            [ClaimsEnum::Exp->value],
            [ClaimsEnum::Cnf->value],
            [ClaimsEnum::Fed->value],
        ],
        CredentialFormatIdentifiersEnum::VcSdJwt->value => [
            [ClaimsEnum::AtContext->value],
            [ClaimsEnum::Id->value],
            [ClaimsEnum::Type->value],
            [ClaimsEnum::Issuer->value],
            [ClaimsEnum::ValidFrom->value],
            [ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value],
            [ClaimsEnum::Iss->value],
            [ClaimsEnum::Iat->value],
            [ClaimsEnum::Nbf->value],
            [ClaimsEnum::Sub->value],
            [ClaimsEnum::Jti->value],
            [ClaimsEnum::Status->value],
            [ClaimsEnum::Exp->value],
            [ClaimsEnum::Cnf->value],
            [ClaimsEnum::ValidUntil->value],
            [ClaimsEnum::Terms_Of_Use->value],
        ],
        CredentialFormatIdentifiersEnum::JwtVcJson->value => [
            [ClaimsEnum::AtContext->value],
            [ClaimsEnum::Type->value],
            [ClaimsEnum::Issuer->value],
            [ClaimsEnum::Issuance_Date->value],
            [ClaimsEnum::Id->value],
            [ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value],
            [ClaimsEnum::Expiration_Date->value],
            [ClaimsEnum::Terms_Of_Use->value],
        ],
    ];


    /**
     * Where a claim path of the configuration puts its claim in a credential of the format, as the Credential
     * Endpoint writes a mapped attribute: as it is for `dc+sd-jwt`; for `vc+sd-jwt` rooted under `credentialSubject`
     * when its parent path does not name it (the disclosures do the same); for `jwt_vc_json` nowhere unless it is
     * under `credentialSubject`, the only member of the subject claims its body keeps. Null where it is nowhere.
     *
     * @return list<mixed>|null
     */
    public function claimPathInCredential(string $credentialFormatId, array $claimPath): ?array
    {
        $claimPath = array_values($claimPath);

        if ($credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value) {
            return ($claimPath[0] ?? null) === ClaimsEnum::Credential_Subject->value ? $claimPath : null;
        }

        if ($credentialFormatId === CredentialFormatIdentifiersEnum::VcSdJwt->value) {
            /** @psalm-suppress MixedAssignment */
            $claimName = array_pop($claimPath);

            if (!in_array(ClaimsEnum::Credential_Subject->value, $claimPath, true)) {
                array_unshift($claimPath, ClaimsEnum::Credential_Subject->value);
            }

            /** @psalm-suppress MixedAssignment */
            $claimPath[] = $claimName;
        }

        return $claimPath;
    }


    /**
     * Where a claim path points in a credential of the format, whatever writes the claim: where
     * claimPathInCredential() puts a mapped attribute, and for a `jwt_vc_json` claim outside `credentialSubject`,
     * which no attribute reaches, the member of the credential it names.
     *
     * @return list<mixed>
     */
    public function locate(string $credentialFormatId, array $claimPath): array
    {
        return $this->claimPathInCredential($credentialFormatId, $claimPath) ?? array_values($claimPath);
    }


    /**
     * Whether the issuer itself writes the claim at a location (locate()), so that whether it is in a credential is
     * not up to the attribute mapping: one it writes, one inside one (what an object the issuer writes holds is the
     * issuer's), or one holding one.
     *
     * @param list<mixed> $location
     */
    public function isWrittenByIssuer(string $credentialFormatId, array $location): bool
    {
        return $this->isWrittenBy($location, self::ISSUER_WRITTEN_CLAIM_PATHS[$credentialFormatId] ?? []);
    }


    /**
     * Whether what is written at the given locations may give the claim at a location: a value written at it,
     * around it (an object written there may hold it) or inside it (a value written inside it brings it into
     * being). A location is compared up to its first index or null, as issuance judges a claim: what is written is
     * written at member names, and which elements of the value there an index or a null selects is not judged.
     * One which starts with an index or a null names no member of the credential, which is an object, so nothing
     * gives it. Member names are compared strictly.
     *
     * @param list<mixed> $location
     * @param list<list<mixed>> $writtenLocations
     */
    public function isWrittenBy(array $location, array $writtenLocations): bool
    {
        $members = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($location as $component) {
            if (!is_string($component)) {
                break;
            }
            $members[] = $component;
        }

        if ($members === []) {
            return false;
        }

        foreach ($writtenLocations as $writtenLocation) {
            $length = min(count($members), count($writtenLocation));

            if (array_slice($members, 0, $length) === array_slice($writtenLocation, 0, $length)) {
                return true;
            }
        }

        return false;
    }
}
