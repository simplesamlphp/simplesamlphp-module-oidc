<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\Menu;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\Menu\Item;

#[CoversClass(Item::class)]
class ItemTest extends TestCase
{
    protected string $hrefPath;
    protected string $label;
    protected string $iconAssetPath;

    protected function setUp(): void
    {
        $this->hrefPath = 'path';
        $this->label = 'label';
        $this->iconAssetPath = 'icon-path';
    }

    protected function sut(
        ?string $hrefPath = null,
        ?string $label = null,
        ?string $iconAssetPath = null,
    ): Item {
        $hrefPath ??= $this->hrefPath;
        $label ??= $this->label;
        $iconAssetPath ??= $this->iconAssetPath;

        return new Item($hrefPath, $label, $iconAssetPath);
    }

    public function testCanCreateInstance(): void
    {
        $sut = $this->sut();
        $this->assertInstanceOf(Item::class, $sut);

        $this->assertSame($sut->getHrefPath(), $this->hrefPath);
        $this->assertSame($sut->getLabel(), $this->label);
        $this->assertSame($sut->getIconAssetPath(), $this->iconAssetPath);
    }
}
