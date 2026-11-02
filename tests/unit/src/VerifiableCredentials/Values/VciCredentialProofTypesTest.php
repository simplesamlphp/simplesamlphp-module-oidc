<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCredentialProofTypes;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements;

#[CoversClass(VciCredentialProofTypes::class)]
class VciCredentialProofTypesTest extends TestCase
{
    protected const array ALGORITHMS = ['ES256', 'RS256'];


    public function testTakesJwtProofsWithoutKeyAttestationsByDefault(): void
    {
        $proofTypes = VciCredentialProofTypes::jwtOnly();

        $this->assertSame([VciProofTypeEnum::Jwt], $proofTypes->getOffered());
        $this->assertTrue($proofTypes->offers(VciProofTypeEnum::Jwt));
        $this->assertFalse($proofTypes->offers(VciProofTypeEnum::Attestation));
        $this->assertFalse($proofTypes->requiresKeyAttestation(VciProofTypeEnum::Jwt));
        $this->assertFalse($proofTypes->requiresKeyAttestation(VciProofTypeEnum::Attestation));
        $this->assertNull($proofTypes->getKeyAttestationRequirementsFor(VciProofTypeEnum::Jwt));
        $this->assertFalse($proofTypes->requiresAnyKeyAttestation());
        $this->assertSame(
            ['jwt' => ['proof_signing_alg_values_supported' => self::ALGORITHMS]],
            $proofTypes->toMetadata(self::ALGORITHMS),
        );
    }


    /**
     * A jwt proof carries a key attestation only where the configuration says so.
     */
    public function testRequiresAKeyAttestationOfAJwtProofWhereItStatesRequirements(): void
    {
        $requirements = new VciKeyAttestationRequirements(['iso_18045_high']);
        $proofTypes = new VciCredentialProofTypes(['jwt' => $requirements]);

        $this->assertTrue($proofTypes->requiresKeyAttestation(VciProofTypeEnum::Jwt));
        $this->assertSame($requirements, $proofTypes->getKeyAttestationRequirementsFor(VciProofTypeEnum::Jwt));
        $this->assertTrue($proofTypes->requiresAnyKeyAttestation());
        $this->assertSame(
            [
                'jwt' => [
                    'proof_signing_alg_values_supported' => self::ALGORITHMS,
                    'key_attestations_required' => ['key_storage' => ['iso_18045_high']],
                ],
            ],
            $proofTypes->toMetadata(self::ALGORITHMS),
        );
    }


    /**
     * An attestation proof is a key attestation, whether or not the configuration states requirements of it, and it
     * publishes key_attestations_required only where it does.
     */
    public function testAnAttestationProofIsAKeyAttestationWithOrWithoutRequirements(): void
    {
        $proofTypes = new VciCredentialProofTypes(['jwt' => null, 'attestation' => null]);

        $this->assertSame([VciProofTypeEnum::Jwt, VciProofTypeEnum::Attestation], $proofTypes->getOffered());
        $this->assertFalse($proofTypes->requiresKeyAttestation(VciProofTypeEnum::Jwt));
        $this->assertTrue($proofTypes->requiresKeyAttestation(VciProofTypeEnum::Attestation));
        $this->assertNull($proofTypes->getKeyAttestationRequirementsFor(VciProofTypeEnum::Attestation));
        $this->assertTrue($proofTypes->requiresAnyKeyAttestation());
        $this->assertSame(
            [
                'jwt' => ['proof_signing_alg_values_supported' => self::ALGORITHMS],
                'attestation' => ['proof_signing_alg_values_supported' => self::ALGORITHMS],
            ],
            $proofTypes->toMetadata(self::ALGORITHMS),
        );
    }


    /**
     * Published in the order configured, and the attestation proof type alone where it is the only one.
     */
    public function testPublishesTheProofTypesInTheOrderConfigured(): void
    {
        $proofTypes = new VciCredentialProofTypes([
            'attestation' => new VciKeyAttestationRequirements(),
            'jwt' => new VciKeyAttestationRequirements(null, ['iso_18045_moderate']),
        ]);

        $this->assertSame([VciProofTypeEnum::Attestation, VciProofTypeEnum::Jwt], $proofTypes->getOffered());
        $this->assertSame('{"attestation":{"proof_signing_alg_values_supported":["ES256","RS256"],' .
            '"key_attestations_required":{}},"jwt":{"proof_signing_alg_values_supported":["ES256","RS256"],' .
            '"key_attestations_required":{"user_authentication":["iso_18045_moderate"]}}}', json_encode(
                $proofTypes->toMetadata(self::ALGORITHMS),
            ));

        // A list with a gap would be a JSON object.
        $this->assertSame(
            '{"attestation":{"proof_signing_alg_values_supported":["ES256","RS256"]}}',
            json_encode(
                (new VciCredentialProofTypes(['attestation' => null]))->toMetadata([0 => 'ES256', 2 => 'RS256']),
            ),
        );

        $attestationOnly = new VciCredentialProofTypes(['attestation' => null]);

        $this->assertFalse($attestationOnly->offers(VciProofTypeEnum::Jwt));
        $this->assertFalse($attestationOnly->requiresKeyAttestation(VciProofTypeEnum::Jwt));
        $this->assertTrue($attestationOnly->requiresAnyKeyAttestation());
    }
}
