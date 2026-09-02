<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Codebooks;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;

#[CoversClass(VciCredentialBindingPolicyEnum::class)]
#[AllowMockObjectsWithoutExpectations]
class VciCredentialBindingPolicyEnumTest extends TestCase
{
    /**
     * What a deployment on the current library can resolve, in the order the registry reports it.
     *
     * @var list<string>
     */
    protected const array RESOLVABLE_DID_METHODS = ['did:jwk', 'did:key', 'did:web'];


    public function testOnlyAProoflessConfigurationIssuesWithoutAKeyProof(): void
    {
        $this->assertTrue(VciCredentialBindingPolicyEnum::ProofBound->requiresKeyProof());
        $this->assertTrue(VciCredentialBindingPolicyEnum::DiipProofBound->requiresKeyProof());
        $this->assertFalse(VciCredentialBindingPolicyEnum::Proofless->requiresKeyProof());
    }


    /**
     * Nothing in OpenID4VCI narrows the holder to particular DID methods, so the default policy takes
     * whatever this deployment can resolve - including a method the library adds after this is written,
     * which is the case this cannot be written as a fixed list to cover.
     */
    public function testTheDefaultPolicyAcceptsAnyResolvableDidMethod(): void
    {
        $policy = VciCredentialBindingPolicyEnum::ProofBound;

        $this->assertSame(
            self::RESOLVABLE_DID_METHODS,
            $policy->acceptableDidMethodsFrom(self::RESOLVABLE_DID_METHODS),
        );
        // Including one the library did not have when this was written, which is the case a fixed list
        // could not cover.
        $this->assertSame(['did:example'], $policy->acceptableDidMethodsFrom(['did:example']));
    }


    public function testADiipConfigurationAcceptsOnlyTheTwoMethodsTheProfileNames(): void
    {
        $policy = VciCredentialBindingPolicyEnum::DiipProofBound;

        $this->assertSame(
            ['did:jwk', 'did:web'],
            // `did:key` is supported by this module and accepted by every other configuration, but not
            // named by the profile.
            $policy->acceptableDidMethodsFrom(['did:jwk', 'did:key', 'did:web', 'did:example']),
        );
    }


    /**
     * Asked, and answered, although no holder identifier reaches a proofless configuration: the
     * metadata side calls this for every policy, and an unanswered case there would be an exception on
     * the published document rather than an omitted field.
     */
    public function testAProoflessConfigurationAcceptsNoHolderIdentifierAtAll(): void
    {
        $this->assertFalse(VciCredentialBindingPolicyEnum::Proofless->acceptsInlineKey());
        $this->assertSame([], VciCredentialBindingPolicyEnum::Proofless->acceptableDidMethodsFrom(
            self::RESOLVABLE_DID_METHODS,
        ));
    }


    public function testOnlyTheDefaultPolicyAcceptsAKeyCarriedInline(): void
    {
        $this->assertTrue(VciCredentialBindingPolicyEnum::ProofBound->acceptsInlineKey());
        // The profile's requirements are written in DID URLs, and an inline key names no verification
        // method for one to point at.
        $this->assertFalse(VciCredentialBindingPolicyEnum::DiipProofBound->acceptsInlineKey());
    }


    /**
     * The registry's own order is kept, so that the advertised list reads the way the library reports
     * it rather than the way a filter happened to rebuild it.
     */
    public function testFilteringTheRegistryKeepsItsOrderAndDropsNothingElse(): void
    {
        $this->assertSame(
            self::RESOLVABLE_DID_METHODS,
            VciCredentialBindingPolicyEnum::ProofBound->acceptableDidMethodsFrom(self::RESOLVABLE_DID_METHODS),
        );
        $this->assertSame(
            ['did:jwk', 'did:web'],
            VciCredentialBindingPolicyEnum::DiipProofBound->acceptableDidMethodsFrom(
                self::RESOLVABLE_DID_METHODS,
            ),
        );
    }


    /**
     * A profile method this deployment can not resolve is not advertised. Publishing it would send a
     * wallet to build a proof the Credential Endpoint would then refuse, since resolution is what
     * accepting a holder identifier actually comes down to.
     */
    public function testAProfileMethodTheDeploymentCanNotResolveIsNotAdvertised(): void
    {
        $this->assertSame(
            ['did:jwk'],
            VciCredentialBindingPolicyEnum::DiipProofBound->bindingMethodsFrom(['did:jwk', 'did:key']),
        );
    }


    public function testTheDefaultPolicyAdvertisesTheRegistryPlusTheInlineKeyValue(): void
    {
        $this->assertSame(
            ['did:jwk', 'did:key', 'did:web', VciCredentialBindingPolicyEnum::BINDING_METHOD_JWK],
            VciCredentialBindingPolicyEnum::ProofBound->bindingMethodsFrom(self::RESOLVABLE_DID_METHODS),
        );
    }


    /**
     * Null rather than an empty list, and the difference matters at the one call site: OpenID4VCI
     * chains `proof_types_supported` to `cryptographic_binding_methods_supported`, so a proofless
     * configuration omits both fields instead of publishing one of them empty.
     */
    public function testAProoflessConfigurationAdvertisesNoBindingAtAll(): void
    {
        $this->assertNull(
            VciCredentialBindingPolicyEnum::Proofless->bindingMethodsFrom(self::RESOLVABLE_DID_METHODS),
        );
    }
}
