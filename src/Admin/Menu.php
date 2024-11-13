<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin;

use SimpleSAML\Module\oidc\Admin\Menu\Item;

class Menu
{
    /**
     * @var array<Item>
     */
    protected array $items = [];

    protected ?string $activeHrefPath = null;

    public function __construct(Item ...$items)
    {
        array_push($this->items, ...$items);
    }

    public function addItem(Item $menuItem, int $offset = null): void
    {
        $offset ??= count($this->items);

        array_splice($this->items, $offset, 0, [$menuItem]);
    }

    public function getItems(): array
    {
        return $this->items;
    }

    public function setActiveHrefPath(?string $value): void
    {
        $this->activeHrefPath = $value;
    }

    public function getActiveHrefPath(): ?string
    {
        return $this->activeHrefPath;
    }

    /**
     * Item factory method for easy injection in tests.
     */
    public function buildItem(string $hrefPath, string $label, ?string $iconAssetPath = null): Item
    {
        return new Item($hrefPath, $label, $iconAssetPath);
    }
}
