<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

interface MementoInterface
{
    /**
     * @return array
     */
    public function getState(): array;
}
