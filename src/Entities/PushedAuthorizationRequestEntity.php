<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2026 by the Spanish Research and Academic Network.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;

class PushedAuthorizationRequestEntity implements MementoInterface
{
    public function __construct(
        protected readonly string $requestUri,
        protected readonly string $clientId,
        protected readonly array $parameters,
        protected readonly DateTimeImmutable $expiresAt,
        protected bool $isConsumed = false,
    ) {
    }

    public function getRequestUri(): string
    {
        return $this->requestUri;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function getExpiresAt(): DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isConsumed(): bool
    {
        return $this->isConsumed;
    }

    public function consume(): void
    {
        $this->isConsumed = true;
    }

    public function isExpired(): bool
    {
        return $this->expiresAt < new DateTimeImmutable();
    }

    /**
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'request_uri' => $this->requestUri,
            'client_id' => $this->clientId,
            'parameters' => json_encode($this->parameters, JSON_THROW_ON_ERROR),
            'expires_at' => $this->expiresAt->format('Y-m-d H:i:s'),
            'is_consumed' => $this->isConsumed,
        ];
    }
}
