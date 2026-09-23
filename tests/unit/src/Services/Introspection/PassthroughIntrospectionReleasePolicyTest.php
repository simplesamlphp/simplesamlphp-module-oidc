<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Introspection;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\Introspection\PassthroughIntrospectionReleasePolicy;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;

#[CoversClass(PassthroughIntrospectionReleasePolicy::class)]
class PassthroughIntrospectionReleasePolicyTest extends TestCase
{
    public function testReleasesTheWholeAnswerToEveryCaller(): void
    {
        $sut = new PassthroughIntrospectionReleasePolicy();

        foreach (
            [
                IntrospectionAuthorization::forClient('client1'),
                IntrospectionAuthorization::forResourceServer('rs1'),
                IntrospectionAuthorization::forUpstreamHub('hub1'),
                IntrospectionAuthorization::forAdministrative('simplesamlphp-admin'),
            ] as $caller
        ) {
            $decision = $sut->decide(
                $caller,
                IntrospectedTokenOrigin::local('https://op.example.org'),
                ['openid', 'profile'],
                ['active' => true, 'sub' => 's1'],
            );

            $this->assertFalse($decision->isDenied());
            $this->assertSame(['openid', 'profile'], $decision->releasedScopesOf(['openid', 'profile']));
            $this->assertSame([], $decision->getWithheldMembers());
        }
    }
}
