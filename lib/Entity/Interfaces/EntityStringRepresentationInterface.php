<?php

namespace SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces;

interface EntityStringRepresentationInterface
{
    /**
     * Generate string representation of entity.
     * @return string
     */
    public function toString(): ?string;
}
