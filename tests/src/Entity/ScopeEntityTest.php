<?php

namespace SimpleSAML\Test\Module\oidc\Entity;

use SimpleSAML\Module\oidc\Entity\ScopeEntity;
use PHPUnit\Framework\TestCase;

class ScopeEntityTest extends TestCase
{
    protected function prepareMockedInstance(
        string $id = 'id',
        string $description = 'description',
        string $icon = 'icon',
        array $attributes = ['attrid' => 'attrval']
    ): ScopeEntity {
        return ScopeEntity::fromData($id, $description, $icon, $attributes);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ScopeEntity::class,
            $this->prepareMockedInstance()
        );
    }

    public function testCanGetProperties(): void
    {
        $scopeEntity = $this->prepareMockedInstance();
        $this->assertSame('id', $scopeEntity->getIdentifier());
        $this->assertSame('description', $scopeEntity->getDescription());
        $this->assertSame('icon', $scopeEntity->getIcon());
        $this->assertSame(['attrid' => 'attrval'], $scopeEntity->getClaims());
        $this->assertSame('id', $scopeEntity->jsonSerialize());
    }
}
