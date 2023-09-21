<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

interface EntityStringRepresentationInterface
{
    /**
     * Generate string representation of entity.
     * @return string
     */
    public function toString(): ?string;
}
