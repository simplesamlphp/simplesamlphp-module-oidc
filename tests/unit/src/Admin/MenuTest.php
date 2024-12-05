<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\Menu;
use SimpleSAML\Module\oidc\Admin\Menu\Item;

#[CoversClass(Menu::class)]
#[UsesClass(Item::class)]
class MenuTest extends TestCase
{
    protected MockObject $itemMock;

    protected function setUp(): void
    {
        $this->itemMock = $this->createMock(Item::class);
    }

    protected function sut(
        ?Item ...$items,
    ): Menu {
        return new Menu(...$items);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(Menu::class, $this->sut());
        $this->assertInstanceOf(Menu::class, $this->sut($this->itemMock));
    }

    public function testCanAddGetItem(): void
    {
        $sut = $this->sut();
        $this->assertEmpty($sut->getItems());
        $sut->addItem($this->itemMock);
        $this->assertCount(1, $sut->getItems());
    }

    public function testCanSetGetActiveHrefPath(): void
    {
        $sut = $this->sut();
        $this->assertNull($sut->getActiveHrefPath());
        $sut->setActiveHrefPath('oidc');
        $this->assertSame('oidc', $sut->getActiveHrefPath());
    }

    public function testCanBuildItem(): void
    {
        $this->assertInstanceOf(Item::class, $this->sut()->buildItem('oidc', 'OIDC'));
    }
}
