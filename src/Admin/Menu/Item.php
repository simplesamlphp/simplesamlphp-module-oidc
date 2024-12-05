<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\Menu;

class Item
{
    public function __construct(
        protected string $hrefPath,
        protected string $label,
        protected ?string $iconAssetPath = null,
    ) {
    }

    public function getHrefPath(): string
    {
        return $this->hrefPath;
    }

    public function getLabel(): string
    {
        return $this->label;
    }

    public function getIconAssetPath(): ?string
    {
        return $this->iconAssetPath;
    }
}
