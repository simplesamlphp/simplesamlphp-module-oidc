<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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


    public static function issuerIdentifierProvider(): array
    {
        return [
            'a host' => ['https://node-a.example.org', true],
            'a path' => ['https://node-a.example.org/oidc/', true],
            'a port' => ['https://node-a.example.org:8443', true],
            'the scheme in capitals' => ['HTTPS://node-a.example.org', true],
            'http' => ['http://node-a.example.org', false],
            'a query' => ['https://node-a.example.org/?tenant=a', false],
            'an empty query' => ['https://node-a.example.org/?', false],
            'a fragment' => ['https://node-a.example.org/#a', false],
            'a user' => ['https://someone@node-a.example.org', false],
            'a user and a password' => ['https://someone:secret@node-a.example.org', false],
            'no host' => ['https:///oidc', false],
            'not a URL' => ['node-a.example.org', false],
            'empty' => ['', false],
        ];
    }


    /**
     * RFC 8414 section 2: "a URL that uses the "https" scheme and has no query or fragment components".
     */
    #[DataProvider('issuerIdentifierProvider')]
    public function testTellsAnIssuerIdentifier(string $value, bool $isIssuerIdentifier): void
    {
        $this->assertSame($isIssuerIdentifier, IntrospectionUpstream::isIssuerIdentifier($value));
    }
}
