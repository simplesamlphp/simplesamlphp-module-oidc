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

use DateTime;
use Exception;
use League\OAuth2\Server\Entities\UserEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class UserEntity implements UserEntityInterface, MementoInterface, ClaimSetInterface
{
    /**
     * @var string
     */
    private string $identifier;

    /**
     * @var array
     */
    private array $claims;

    /**
     * @var DateTime
     */
    private DateTime $createdAt;

    /**
     * @var DateTime
     */
    private DateTime $updatedAt;

    private function __construct()
    {
    }

    /**
     * @throws Exception
     */
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
     * @throws OidcServerException
     * @throws Exception
     * @throws Exception
     */
    public static function fromState(array $state): self
    {
        $user = new self();

        if (
            !is_string($state['id']) ||
            !is_string($state['claims']) ||
            !is_string($state['updated_at']) ||
            !is_string($state['created_at'])
        ) {
            throw OidcServerException::serverError('Invalid user entity data');
        }

        $user->identifier = $state['id'];
        $claims = json_decode($state['claims'], true, 512, JSON_INVALID_UTF8_SUBSTITUTE);

        if (!is_array($claims)) {
            throw OidcServerException::serverError('Invalid user entity data');
        }
        $user->claims = $claims;
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

    /**
     * @throws Exception
     */
    public function setClaims(array $claims): self
    {
        $this->claims = $claims;
        $this->updatedAt = TimestampGenerator::utc();

        return $this;
    }

    public function getUpdatedAt(): DateTime
    {
        return $this->updatedAt;
    }

    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }
}
