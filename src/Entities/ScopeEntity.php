<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * @param string[] $claims
     */
    public function __construct(
        string $identifier,
        protected ?string $description = null,
        protected ?string $icon = null,
        protected array $claims = [],
    ) {
        $this->identifier = $identifier;
    }

    public function getIcon(): ?string
    {
        return $this->icon;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return array<string>
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    public function jsonSerialize(): string
    {
        return (string) $this->getIdentifier();
    }
}
