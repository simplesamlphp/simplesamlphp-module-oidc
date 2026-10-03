<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entities\Traits\FormatForDatabaseTrait;

class PushedAuthorizationRequestEntity implements MementoInterface
{
    use FormatForDatabaseTrait;


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


    public function isExpired(DateTimeImmutable $now): bool
    {
        return $this->expiresAt < $now;
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
            'expires_at' => $this->formatForDatabase($this->expiresAt),
            'is_consumed' => $this->isConsumed,
        ];
    }
}
