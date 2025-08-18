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

use DateTimeImmutable;
use League\OAuth2\Server\Entities\ClientEntityInterface as OAuth2ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entities\Traits\OidcAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;

class AuthCodeEntity implements AuthCodeEntityInterface, MementoInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use OidcAuthCodeTrait;
    use RevokeTokenTrait;

    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    public function __construct(
        string $id,
        OAuth2ClientEntityInterface $client,
        array $scopes,
        DateTimeImmutable $expiryDateTime,
        ?string $userIdentifier = null,
        ?string $redirectUri = null,
        ?string $nonce = null,
        bool $isRevoked = false,
        protected readonly bool $isPreAuthorized = false,
        protected readonly ?string $txCode = null,
    ) {
        $this->identifier = $id;
        $this->client = $client;
        $this->scopes = $scopes;
        $this->expiryDateTime = $expiryDateTime;
        $this->userIdentifier = $userIdentifier;
        $this->redirectUri = $redirectUri;
        $this->nonce = $nonce;
        $this->isRevoked = $isRevoked;
    }

    /**
     * @throws \JsonException
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->client->getIdentifier(),
            'is_revoked' => $this->isRevoked(),
            'redirect_uri' => $this->getRedirectUri(),
            'nonce' => $this->getNonce(),
            'is_pre_authorized' => $this->isPreAuthorized,
            'tx_code' => $this->txCode,
        ];
    }

    public function isPreAuthorized(): bool
    {
        return $this->isPreAuthorized;
    }

    public function getTxCode(): ?string
    {
        return $this->txCode;
    }
}
