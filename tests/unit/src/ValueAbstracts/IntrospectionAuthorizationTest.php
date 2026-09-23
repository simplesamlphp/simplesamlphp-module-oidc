<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\IntrospectionCallerRoleEnum;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;

#[CoversClass(IntrospectionAuthorization::class)]
#[AllowMockObjectsWithoutExpectations]
class IntrospectionAuthorizationTest extends TestCase
{
    /**
     * Every role keeps who the caller is, which a release decision, a rate limit and a log line need.
     */
    #[DataProvider('callerProvider')]
    public function testKeepsTheCallersRoleAndIdentity(
        IntrospectionAuthorization $sut,
        IntrospectionCallerRoleEnum $expectedRole,
        string $expectedCallerId,
    ): void {
        $this->assertSame($expectedRole, $sut->getRole());
        $this->assertSame($expectedCallerId, $sut->getCallerId());
    }


    public static function callerProvider(): array
    {
        return [
            'a client' => [
                IntrospectionAuthorization::forClient('client-id'),
                IntrospectionCallerRoleEnum::Client,
                'client-id',
            ],
            'a resource server' => [
                IntrospectionAuthorization::forResourceServer('resource-server'),
                IntrospectionCallerRoleEnum::ResourceServer,
                'resource-server',
            ],
            'the upstream hub' => [
                IntrospectionAuthorization::forUpstreamHub('hub'),
                IntrospectionCallerRoleEnum::UpstreamHub,
                'hub',
            ],
            'an administrator or an API token' => [
                IntrospectionAuthorization::forAdministrative('HR system'),
                IntrospectionCallerRoleEnum::Administrative,
                'HR system',
            ],
        ];
    }


    /**
     * A resource server, the upstream hub and the administrative path are each trusted with every token this
     * OP issued, including one whose owner could not be established.
     */
    #[DataProvider('trustedWithAnyTokenProvider')]
    public function testCallerTrustedWithAnyTokenIsNotLimitedToAClient(IntrospectionAuthorization $sut): void
    {
        $this->assertTrue($sut->mayIntrospectTokenOf('client-id'));
        $this->assertTrue($sut->mayIntrospectTokenOf('some-other-client-id'));
        $this->assertTrue($sut->mayIntrospectTokenOf(null));
    }


    public static function trustedWithAnyTokenProvider(): array
    {
        return [
            'a resource server' => [IntrospectionAuthorization::forResourceServer('resource-server')],
            'the upstream hub' => [IntrospectionAuthorization::forUpstreamHub('hub')],
            'an administrator or an API token' => [IntrospectionAuthorization::forAdministrative('HR system')],
        ];
    }


    public function testClientMayOnlyIntrospectItsOwnTokens(): void
    {
        $sut = IntrospectionAuthorization::forClient('client-id');

        $this->assertTrue($sut->mayIntrospectTokenOf('client-id'));
        $this->assertFalse($sut->mayIntrospectTokenOf('some-other-client-id'));
    }


    public function testClientMayNotIntrospectTokenWithoutEstablishedOwner(): void
    {
        $this->assertFalse(IntrospectionAuthorization::forClient('client-id')->mayIntrospectTokenOf(null));
    }


    /**
     * Identifiers are compared as they are: a client which registered under a differently cased identifier
     * is a different client, so it is not to be told about this one's tokens.
     */
    public function testClientIdComparisonIsCaseSensitive(): void
    {
        $this->assertFalse(IntrospectionAuthorization::forClient('client-id')->mayIntrospectTokenOf('CLIENT-ID'));
    }


    /**
     * Only a client is held to its own tokens: an administrative principal which happens to equal a client's
     * identifier is not a client, and is not narrowed to that client's tokens.
     */
    public function testOnlyTheClientRoleComparesTheOwner(): void
    {
        $this->assertTrue(
            IntrospectionAuthorization::forAdministrative('client-id')->mayIntrospectTokenOf('some-other-client-id'),
        );
    }
}
