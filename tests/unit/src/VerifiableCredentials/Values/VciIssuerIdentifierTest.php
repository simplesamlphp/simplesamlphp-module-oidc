<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;

#[CoversClass(VciIssuerIdentifier::class)]
class VciIssuerIdentifierTest extends TestCase
{
    protected const string DID_WEB = 'did:web:example.org';


    public function testCanBeBuiltWithoutADidWeb(): void
    {
        $identifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk);

        $this->assertSame(VciIssuerIdentifierModeEnum::DidJwk, $identifier->getMode());
        $this->assertNull($identifier->getDidWeb());
        $this->assertFalse($identifier->isIssuingUnderDidWeb());
    }


    public function testCarriesTheDidWebItIssuesUnder(): void
    {
        $identifier = new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB);

        $this->assertSame(self::DID_WEB, $identifier->getDidWeb());
        $this->assertTrue($identifier->isIssuingUnderDidWeb());
    }


    /**
     * The state which keeps a published document alive after the deployment stopped issuing under it.
     */
    public function testKeepsADidWebWhichIsNoLongerIssuedUnder(): void
    {
        foreach ([VciIssuerIdentifierModeEnum::DidJwk, VciIssuerIdentifierModeEnum::Https] as $mode) {
            $identifier = new VciIssuerIdentifier($mode, self::DID_WEB);

            $this->assertSame(self::DID_WEB, $identifier->getDidWeb());
            $this->assertFalse(
                $identifier->isIssuingUnderDidWeb(),
                'The DID is published, but nothing is issued under it.',
            );
        }
    }


    public function testRefusesDidWebModeWithoutADidWeb(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage(VciIssuerIdentifierModeEnum::DidWeb->value);

        new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb);
    }
}
