<?php

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

namespace SimpleSAML\Modules\OpenIDConnect\Entity;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ScopeEntity implements ScopeEntityInterface
{
    use EntityTrait;

    /**
     * @var string
     */
    private $icon;

    /**
     * @var string
     */
    private $description;

    /**
     * @var array
     */
    private $attributes;


    /**
     * Constructor
     */
    private function __construct()
    {
    }


    /**
     * @param string $identifier
     * @param string|null $description
     * @param string|null $icon
     * @param array $attributes
     * @return self
     */
    public static function fromData(string $identifier, string $description = null, string $icon = null, array $attributes = []): self
    {
        $scope = new self();

        $scope->identifier = $identifier;
        $scope->description = $description;
        $scope->icon = $icon;
        $scope->attributes = $attributes;

        return $scope;
    }


    /**
     * @return string
     */
    public function getIcon(): string
    {
        return $this->icon;
    }


    /**
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }


    /**
     * @return array
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }


    /**
     * @return string
     */
    public function jsonSerialize(): string
    {
        return $this->getIdentifier();
    }
}
