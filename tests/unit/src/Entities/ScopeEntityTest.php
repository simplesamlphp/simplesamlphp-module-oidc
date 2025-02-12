<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Entities;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;

class ScopeEntityTest extends TestCase
{
    protected function mock(
        string $id = 'id',
        string $description = 'description',
        string $icon = 'icon',
        array $attributes = ['attrid' => 'attrval'],
    ): ScopeEntity {
        return new ScopeEntity($id, $description, $icon, $attributes);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ScopeEntity::class,
            $this->mock(),
        );
    }

    public function testCanGetProperties(): void
    {
        $scopeEntity = $this->mock();
        $this->assertSame('id', $scopeEntity->getIdentifier());
        $this->assertSame('description', $scopeEntity->getDescription());
        $this->assertSame('icon', $scopeEntity->getIcon());
        $this->assertSame(['attrid' => 'attrval'], $scopeEntity->getClaims());
        $this->assertSame('id', $scopeEntity->jsonSerialize());
    }
}
