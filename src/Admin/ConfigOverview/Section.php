<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

/**
 * A group of related configuration overview rows, rendered as one table with its own heading.
 */
class Section
{
    /**
     * @var \SimpleSAML\Module\oidc\Admin\ConfigOverview\Row[]
     */
    protected array $rows;

    /**
     * @param string $title Section heading.
     * @param string $anchor Fragment identifier, used for in-page navigation.
     */
    public function __construct(
        protected readonly string $title,
        protected readonly string $anchor,
        Row ...$rows,
    ) {
        $this->rows = $rows;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function getAnchor(): string
    {
        return $this->anchor;
    }

    /**
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Row[]
     */
    public function getRows(): array
    {
        return $this->rows;
    }
}
