<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * The key proof types a credential configuration can offer, of those OpenID4VCI 1.0 Appendix F defines: the two this
 * issuer verifies. `di_vp` (F.2) is not one of them.
 */
enum VciProofTypeEnum: string
{
    /**
     * A JWT proving possession of the key the credential is bound to (F.1), which may carry a key attestation in its
     * `key_attestation` header.
     */
    case Jwt = 'jwt';

    /**
     * A key attestation on its own (F.3), without a proof of possession of the keys it attests: one credential is
     * issued for each of them.
     */
    case Attestation = 'attestation';
}
