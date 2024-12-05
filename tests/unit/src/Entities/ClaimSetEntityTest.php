<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ClaimSetEntity;

#[CoversClass(ClaimSetEntity::class)]
class ClaimSetEntityTest extends TestCase
{
    public function testCanCreateInstance(): void
    {
        $sut = new ClaimSetEntity('scope', ['claim']);

        $this->assertInstanceOf(ClaimSetEntity::class, $sut);
        $this->assertSame('scope', $sut->getScope());
        $this->assertSame(['claim'], $sut->getClaims());
    }
}
