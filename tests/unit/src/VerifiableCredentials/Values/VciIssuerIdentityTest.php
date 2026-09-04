<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;

#[CoversClass(VciIssuerIdentity::class)]
class VciIssuerIdentityTest extends TestCase
{
    public function testCarriesTheIssuerTheKeyIdAndTheModeTheyCameFrom(): void
    {
        $identity = new VciIssuerIdentity(
            VciIssuerIdentifierModeEnum::DidWeb,
            'did:web:example.org',
            'did:web:example.org#key-01',
        );

        $this->assertSame(VciIssuerIdentifierModeEnum::DidWeb, $identity->getMode());
        $this->assertSame('did:web:example.org', $identity->getIssuer());
        $this->assertSame('did:web:example.org#key-01', $identity->getKeyId());
    }
}
