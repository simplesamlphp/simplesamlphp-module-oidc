<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

interface EntityStringRepresentationInterface
{
    /**
     * Generate string representation of entity.
     */
    public function toString(): ?string;
}
