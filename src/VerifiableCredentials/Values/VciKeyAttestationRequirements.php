<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use stdClass;

/**
 * What a credential configuration requires of the key attestations sent with one of its proof types: the
 * `key_attestations_required` object of its metadata (OpenID4VCI 1.0 section 12.2.4). For each of the two components
 * it names, the values it accepts (Appendix D.2), of which a key attestation has to state at least one; a component
 * it leaves out is not required. With neither, a key attestation is required "without additional constraints".
 *
 * The values are matched as they are written. The four ISO/IEC 18045 values of Appendix D.2 are ordered, but values
 * an ecosystem defines need not be, so a configuration which accepts a level "or better" lists each level it
 * accepts.
 */
class VciKeyAttestationRequirements
{
    /**
     * @param ?non-empty-list<non-empty-string> $keyStorage The `key_storage` values accepted, or null when the
     * component is not required.
     * @param ?non-empty-list<non-empty-string> $userAuthentication The `user_authentication` values accepted, or
     * null when the component is not required.
     */
    public function __construct(
        protected readonly ?array $keyStorage = null,
        protected readonly ?array $userAuthentication = null,
    ) {
    }


    /**
     * @return ?non-empty-list<non-empty-string>
     */
    public function getKeyStorage(): ?array
    {
        return $this->keyStorage;
    }


    /**
     * @return ?non-empty-list<non-empty-string>
     */
    public function getUserAuthentication(): ?array
    {
        return $this->userAuthentication;
    }


    /**
     * The `key_attestations_required` object as published. Without a component it is an empty JSON object, which a
     * PHP array would encode as an empty JSON array.
     *
     * @return array<string,non-empty-list<non-empty-string>>|\stdClass
     */
    public function toMetadata(): array|stdClass
    {
        $metadata = [];

        if ($this->keyStorage !== null) {
            $metadata[ClaimsEnum::KeyStorage->value] = $this->keyStorage;
        }

        if ($this->userAuthentication !== null) {
            $metadata[ClaimsEnum::UserAuthentication->value] = $this->userAuthentication;
        }

        return $metadata === [] ? new stdClass() : $metadata;
    }
}
