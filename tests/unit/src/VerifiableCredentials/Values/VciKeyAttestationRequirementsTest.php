<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements;
use stdClass;

#[CoversClass(VciKeyAttestationRequirements::class)]
class VciKeyAttestationRequirementsTest extends TestCase
{
    public function testPublishesTheComponentsItRequires(): void
    {
        $requirements = new VciKeyAttestationRequirements(['iso_18045_high'], ['iso_18045_moderate', 'iso_18045_high']);

        $this->assertSame(['iso_18045_high'], $requirements->getKeyStorage());
        $this->assertSame(['iso_18045_moderate', 'iso_18045_high'], $requirements->getUserAuthentication());
        $this->assertSame(
            [
                'key_storage' => ['iso_18045_high'],
                'user_authentication' => ['iso_18045_moderate', 'iso_18045_high'],
            ],
            $requirements->toMetadata(),
        );
    }


    public function testLeavesOutAComponentItDoesNotRequire(): void
    {
        $requirements = new VciKeyAttestationRequirements(null, ['iso_18045_moderate']);

        $this->assertNull($requirements->getKeyStorage());
        $this->assertSame(['user_authentication' => ['iso_18045_moderate']], $requirements->toMetadata());
    }


    /**
     * Section 12.2.4: "the key_attestations_required parameter may be empty, indicating a key attestation is needed
     * without additional constraints". An empty object, which an empty PHP array would not encode as.
     */
    public function testPublishesAnEmptyObjectWithoutComponents(): void
    {
        $metadata = (new VciKeyAttestationRequirements())->toMetadata();

        $this->assertInstanceOf(stdClass::class, $metadata);
        $this->assertSame('{}', json_encode($metadata));
    }
}
