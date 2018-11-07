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

use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

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
    public static function fromState(array $state)
    {
        $user = new self();

        $user->identifier = $state['id'];
        $user->claims = json_decode($state['claims'], true);
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
            'id' => $this->identifier,
            'claims' => json_encode($this->claims),
            'updated_at' => $this->updatedAt->format('Y-m-d H:i:s'),
            'created_at' => $this->createdAt->format('Y-m-d H:i:s'),
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
