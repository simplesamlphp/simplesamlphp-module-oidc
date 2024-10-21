<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use SimpleSAML\Module\oidc\Entities\ScopeEntity;

class ScopeEntityFactory
{
    /**
     * @param string[] $claims
     */
    public function fromData(
        string $identifier,
        string $description = null,
        string $icon = null,
        array $claims = [],
    ): ScopeEntity {
        return new ScopeEntity(
            $identifier,
            $description,
            $icon,
            $claims,
        );
    }
}
