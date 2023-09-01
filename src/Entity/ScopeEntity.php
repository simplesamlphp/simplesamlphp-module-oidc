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

namespace SimpleSAML\Module\oidc\Entity;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * @var string|null
     */
    private ?string $icon;

    /**
     * @var string|null
     */
    private ?string $description;

    /**
     * @var array<string>
     */
    private array $claims;

    private function __construct()
    {
    }

    /**
     * @param array<string> $claims
     */
    public static function fromData(
        string $identifier,
        string $description = null,
        string $icon = null,
        array $claims = []
    ): self {
        $scope = new self();

        $scope->identifier = $identifier;
        $scope->description = $description;
        $scope->icon = $icon;
        $scope->claims = $claims;

        return $scope;
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
        return $this->getIdentifier();
    }
}
