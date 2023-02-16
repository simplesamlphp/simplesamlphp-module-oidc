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

namespace SimpleSAML\Module\oidc\Entity;

use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class UserEntity implements UserEntityInterface, MementoInterface, ClaimSetInterface
{
    /**
     * @var string
     */
    private $identifier;

    /**
     * @var array
     */
    private $claims;

    /**
     * @var \DateTime
     */
    private $createdAt;

    /**
     * @var \DateTime
     */
    private $updatedAt;

    /**
     * Constructor.
     */
    private function __construct()
    {
    }

    public static function fromData(string $identifier, array $claims = []): self
    {
        $user = new self();

        $user->identifier = $identifier;
        $user->createdAt = TimestampGenerator::utc();
        $user->updatedAt = $user->createdAt;
        $user->claims = $claims;

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromState(array $state): self
    {
        $user = new self();

        $user->identifier = $state['id'];
        $user->claims = json_decode($state['claims'], true, 512, JSON_INVALID_UTF8_SUBSTITUTE);
        $user->updatedAt = TimestampGenerator::utc($state['updated_at']);
        $user->createdAt = TimestampGenerator::utc($state['created_at']);

        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'claims' => json_encode($this->getClaims(), JSON_INVALID_UTF8_SUBSTITUTE),
            'updated_at' => $this->getUpdatedAt()->format('Y-m-d H:i:s'),
            'created_at' => $this->getCreatedAt()->format('Y-m-d H:i:s'),
        ];
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function setClaims(array $claims): self
    {
        $this->claims = $claims;
        $this->updatedAt = TimestampGenerator::utc();

        return $this;
    }

    public function getUpdatedAt(): \DateTime
    {
        return $this->updatedAt;
    }

    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }
}
