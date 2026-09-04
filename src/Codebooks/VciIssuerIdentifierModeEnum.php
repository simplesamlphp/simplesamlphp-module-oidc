<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * How an issued Verifiable Credential names the issuer which signed it.
 *
 * The `iss` claim and the `kid` header have to be resolvable by whoever verifies the credential, and
 * which identifier that party can resolve is a property of the deployment rather than of the
 * specification. This enum names the kinds of identity this module can issue under; where one of them
 * needs a value rather than deriving it, that value is an option of its own.
 *
 * The mode is read at issuance, so changing it affects newly issued credentials only. Credentials
 * already in wallets carry the identity they were issued with and keep resolving through it, which is
 * why the did:web document keeps being published for as long as the identifier stays configured -
 * see {@see \SimpleSAML\Module\oidc\ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER}.
 */
enum VciIssuerIdentifierModeEnum: string
{
    /**
     * `iss` is a `did:jwk` derived from the active signing key and `kid` is that DID with the `#0`
     * fragment the method defines. The credential carries the key with it, so it verifies without any
     * lookup at all. Note that this establishes integrity only: whoever verifies it must still bind
     * the DID to the issuer they expect by their own means.
     */
    case DidJwk = 'did_jwk';

    /**
     * `iss` is the configured `did:web` and `kid` names one verification method inside the DID
     * document this module publishes. Resolvable by anyone, and bound to a domain name, which is what
     * the DIIP profile asks of an issuer.
     */
    case DidWeb = 'did_web';

    /**
     * `iss` is this module's issuer URL and `kid` is the JWKS key identifier, so the key is resolved
     * through the published key set. This is what makes the `.well-known/jwt-vc-issuer` document
     * coherent, and it is a way out for deployments whose verifiers will not accept a DID at all.
     *
     * Not DIIP conformant on its own: the profile requires the issuer to be identified by a DID.
     */
    case Https = 'https';
}
