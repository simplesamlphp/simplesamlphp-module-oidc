<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * Whether a credential configuration binds the credentials it issues to a key the wallet proves it holds.
 *
 * OpenID4VCI chains the two halves of this together: `proof_types_supported` must be present in a
 * credential configuration whenever `cryptographic_binding_methods_supported` is, and a Credential
 * Request must carry `proofs` whenever the configuration advertises `proof_types_supported`. So the
 * choice cannot be made per metadata field, and it cannot be made per request either -- it belongs to
 * the configuration, and it governs what is advertised and what is accepted at the same time.
 *
 * Advertising binding and then issuing without it, which is what this module did before, tells a wallet
 * the credential it received is held to its key when nothing of the sort was checked.
 */
enum VciCredentialBindingPolicyEnum: string
{
    /**
     * What OpenID4VCI calls a credential bound to a key given in JWK format, which is what a key proof
     * carrying its key inline in a `jwk` header produces.
     *
     * Not a DID method, so it never comes from the resolver registry and has to be stated here.
     */
    public const string BINDING_METHOD_JWK = 'jwk';

    /**
     * The DID methods the DIIP profile names for a holder, spelled the way the DID Specification
     * Registries spell a method - which is also the spelling `cryptographic_binding_methods_supported`
     * uses, and what {@see \SimpleSAML\OpenID\Did::supportedMethods()} returns.
     *
     * @var list<string>
     */
    protected const array DIIP_BINDING_METHODS = ['did:jwk', 'did:web'];


    /**
     * The default. A Key Proof is required, verified, and the credential is issued to the holder
     * identifier that proof resolves to. Both binding metadata fields are advertised.
     */
    case ProofBound = 'proof_bound';

    /**
     * Everything ProofBound requires, plus the identifier rules the DIIP profile writes on top of
     * OpenID4VCI. The proof's `kid` header must be an absolute DID URL of a `did:jwk` or a `did:web`,
     * and the verification method it names must appear in that document's `authentication`
     * relationship.
     *
     * Two consequences, both about the `kid` header, since that is where this profile's holder binding
     * lives:
     *
     * - A key proof carrying its key inline in a `jwk` header is refused. The requirement is written in
     *   DID URLs, and an inline key names no verification method to point at.
     * - A `did:key` holder is refused, since the profile names the other two. Every other configuration
     *   keeps accepting one.
     *
     * The `iss` claim is left to OpenID4VCI: the client the access token was issued to when there is
     * one, absent when there is not. The profile's own text asks for the holder's DID there, which
     * cannot hold at the same time as OpenID4VCI's rule for an anonymous pre-authorized code;
     * FIDEScommunity/DIIP#83 proposes dropping it in favour of the `kid` rule above, and that is what
     * this implements. A wallet identified by a DID still works - it is accepted, not required, and no
     * part of holder binding rests on it.
     *
     * Every other credential configuration is unaffected: DIIP's requirements are additive, so a
     * deployment can offer conformant configurations alongside ones which accept inline keys or
     * `did:key` holders.
     */
    case DiipProofBound = 'diip_proof_bound';

    /**
     * Credentials are issued unbound, to a subject identifier this issuer derives from the
     * authenticated user. Neither binding metadata field is advertised, and a Key Proof sent anyway is
     * refused: nothing told the wallet which proof type or signing algorithm to produce one with, so
     * accepting it would mean honouring a proof this configuration never asked for.
     */
    case Proofless = 'proofless';


    /**
     * Whether this policy requires a Key Proof at all, which is what decides both halves of the binding
     * metadata and whether a Credential Request has to carry `proofs`.
     *
     * Asked as a question rather than compared against a case, so that a policy added later has to
     * answer it here instead of falling into whichever branch an `if` happened to leave open.
     */
    public function requiresKeyProof(): bool
    {
        return match ($this) {
            self::ProofBound, self::DiipProofBound => true,
            self::Proofless => false,
        };
    }


    /**
     * Whether a holder identified by this DID method is acceptable under this policy.
     *
     * Asked about one method rather than about which profile is in force, deliberately. A caller told
     * only that the DIIP rules apply still has to know what they say, so the profile's method list ends
     * up written out at every such caller - which is how the metadata and the proof validator came to
     * hold one list each, free to disagree.
     *
     * This is the single question behind both halves of the identifier rules: the metadata advertises
     * the methods this deployment can resolve which pass it, and a key proof is refused when the method
     * its `kid` names does not. Answering it in one place is what keeps the two from drifting apart -
     * a method added to the resolver registry becomes acceptable and advertised together, or neither.
     *
     * Not public, deliberately. On its own it answers only what the profile narrows, which is never the
     * whole answer: a method this deployment can not resolve is not one it accepts either. Callers go
     * through {@see acceptableDidMethodsFrom()}, which asks both questions at once and so cannot be
     * used to accept something the metadata does not advertise.
     *
     * @param string $didMethod The method spelled with its `did:` prefix, as
     *        {@see \SimpleSAML\OpenID\Did::supportedMethods()} spells it.
     */
    protected function acceptsDidMethod(string $didMethod): bool
    {
        return match ($this) {
            // Whatever this deployment can resolve. Nothing in OpenID4VCI narrows the holder to a
            // particular method, and narrowing it here would refuse a holder for using a method whose
            // support this issuer went on to advertise.
            self::ProofBound => true,
            self::DiipProofBound => in_array($didMethod, self::DIIP_BINDING_METHODS, true),
            // Never asked: a proofless configuration validates no proof, so no holder identifier of any
            // kind reaches this. Answered all the same, so that the metadata side gets a list rather
            // than an exception if it ever does.
            self::Proofless => false,
        };
    }


    /**
     * Which of the DID methods this deployment can resolve are acceptable under this policy.
     *
     * @param list<string> $didMethods Prefixed method names, ordinarily the whole resolver registry.
     * @return list<string>
     */
    public function acceptableDidMethodsFrom(array $didMethods): array
    {
        return array_values(array_filter($didMethods, $this->acceptsDidMethod(...)));
    }


    /**
     * Whether a key proof may carry its key inline in a `jwk` header rather than naming a verification
     * method in a `kid` header.
     *
     * Kept next to {@see acceptsDidMethod()} because the metadata says so in the same field: a policy
     * accepting inline keys advertises `jwk` alongside its DID methods.
     */
    public function acceptsInlineKey(): bool
    {
        return match ($this) {
            self::ProofBound => true,
            // The profile's requirements are written in DID URLs, and an inline key names no
            // verification method for one to point at.
            self::DiipProofBound => false,
            self::Proofless => false,
        };
    }


    /**
     * The value of `cryptographic_binding_methods_supported` for this policy, given what this
     * deployment can actually resolve.
     *
     * @param list<string> $resolvableDidMethods What {@see \SimpleSAML\OpenID\Did::supportedMethods()}
     *        reports, so that a method the library gains is advertised without this being touched, and
     *        one it loses stops being advertised the same way.
     * @return ?list<string> Null where the policy binds nothing at all, which the caller must tell apart
     *         from an empty list: the field is omitted entirely rather than published empty.
     */
    public function bindingMethodsFrom(array $resolvableDidMethods): ?array
    {
        if (!$this->requiresKeyProof()) {
            return null;
        }

        $bindingMethods = $this->acceptableDidMethodsFrom($resolvableDidMethods);

        if ($this->acceptsInlineKey()) {
            $bindingMethods[] = self::BINDING_METHOD_JWK;
        }

        return $bindingMethods;
    }
}
