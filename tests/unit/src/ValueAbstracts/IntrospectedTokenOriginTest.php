<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\ValueAbstracts;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;

#[CoversClass(IntrospectedTokenOrigin::class)]
class IntrospectedTokenOriginTest extends TestCase
{
    public function testALocalTokensIssuerIsVerified(): void
    {
        $sut = IntrospectedTokenOrigin::local('https://op.example.org');

        $this->assertTrue($sut->isLocal());
        $this->assertSame('https://op.example.org', $sut->getIssuer());
        $this->assertTrue($sut->isIssuerVerified());
    }


    public function testAForeignTokenKeepsWhetherItsIssuerIsVerified(): void
    {
        $verified = IntrospectedTokenOrigin::foreign('https://node-x.example.org', true);
        $unverified = IntrospectedTokenOrigin::foreign('https://node-y.example.org', false);

        $this->assertFalse($verified->isLocal());
        $this->assertSame('https://node-x.example.org', $verified->getIssuer());
        $this->assertTrue($verified->isIssuerVerified());

        $this->assertFalse($unverified->isLocal());
        $this->assertSame('https://node-y.example.org', $unverified->getIssuer());
        $this->assertFalse($unverified->isIssuerVerified());
    }
}
