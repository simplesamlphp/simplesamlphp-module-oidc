<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Entities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClaimSetEntityFactory;

#[CoversClass(ClaimSetEntityFactory::class)]
#[UsesClass(ClaimSetEntity::class)]
class ClaimSetEntityFactoryTest extends TestCase
{
    protected function sut(): ClaimSetEntityFactory
    {
        return new ClaimSetEntityFactory();
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ClaimSetEntityFactory::class, $this->sut());
    }


    public function testBuildPassesScopeAndClaimsThrough(): void
    {
        $entity = $this->sut()->build('profile', ['name', 'family_name']);

        $this->assertSame('profile', $entity->getScope());
        $this->assertSame(['name', 'family_name'], $entity->getClaims());
    }


    public function testBuildAcceptsAScopeWithNoClaims(): void
    {
        $this->assertSame([], $this->sut()->build('openid', [])->getClaims());
    }
}
