<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;

#[CoversClass(IntrospectionAuthorization::class)]
class IntrospectionAuthorizationTest extends TestCase
{
    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(IntrospectionAuthorization::class, IntrospectionAuthorization::forAnyToken());
        $this->assertInstanceOf(
            IntrospectionAuthorization::class,
            IntrospectionAuthorization::forTokensOfClient('client-id'),
        );
    }

    public function testCallerTrustedWithAnyTokenIsNotLimitedToAClient(): void
    {
        $sut = IntrospectionAuthorization::forAnyToken();

        $this->assertNull($sut->getClientId());
        $this->assertTrue($sut->mayIntrospectTokenOf('client-id'));
        $this->assertTrue($sut->mayIntrospectTokenOf('some-other-client-id'));
        $this->assertTrue($sut->mayIntrospectTokenOf(null));
    }

    public function testClientMayOnlyIntrospectItsOwnTokens(): void
    {
        $sut = IntrospectionAuthorization::forTokensOfClient('client-id');

        $this->assertSame('client-id', $sut->getClientId());
        $this->assertTrue($sut->mayIntrospectTokenOf('client-id'));
        $this->assertFalse($sut->mayIntrospectTokenOf('some-other-client-id'));
    }

    public function testClientMayNotIntrospectTokenWithoutEstablishedOwner(): void
    {
        $this->assertFalse(IntrospectionAuthorization::forTokensOfClient('client-id')->mayIntrospectTokenOf(null));
    }

    /**
     * Identifiers are compared as they are: a client which registered under a differently cased identifier
     * is a different client, so it is not to be told about this one's tokens.
     */
    public function testClientIdComparisonIsCaseSensitive(): void
    {
        $this->assertFalse(IntrospectionAuthorization::forTokensOfClient('client-id')->mayIntrospectTokenOf(
            'CLIENT-ID',
        ));
    }
}
