<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionUpstream;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

#[CoversClass(IntrospectionUpstream::class)]
class IntrospectionUpstreamTest extends TestCase
{
    public function testHoldsWhatItWasBuiltWith(): void
    {
        $sut = new IntrospectionUpstream(
            'https://hub.example.org/',
            'https://hub.example.org/introspect',
            'our-client-id',
            'our-client-secret',
            ClientAuthenticationMethodsEnum::ClientSecretPost,
            1.5,
            4.0,
        );

        $this->assertSame('https://hub.example.org/', $sut->getIssuer());
        $this->assertSame('https://hub.example.org/introspect', $sut->getIntrospectionEndpoint());
        $this->assertSame('our-client-id', $sut->getClientId());
        $this->assertSame('our-client-secret', $sut->getClientSecret());
        $this->assertSame(ClientAuthenticationMethodsEnum::ClientSecretPost, $sut->getClientAuthenticationMethod());
        $this->assertSame(1.5, $sut->getConnectTimeout());
        $this->assertSame(4.0, $sut->getTimeout());
    }
}
