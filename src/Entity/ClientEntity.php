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

use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;

    private string $secret;

    private string $description;

    private ?string $authSource;

    /**
     * @var string[] $scopes
     */
    private array $scopes;

    private bool $isEnabled;

    private ?string $owner;

    /**
     * @var string[]|null
     */
    private ?array $postLogoutRedirectUri;

    private ?string $backChannelLogoutUri;

    /**
     * Constructor.
     */
    private function __construct()
    {
        $this->isEnabled = true;
    }

    /**
     * @param string $id
     * @param string $secret
     * @param string $name
     * @param string $description
     * @param string[] $redirectUri
     * @param string[] $scopes
     * @param bool $isEnabled
     * @param bool $isConfidential
     * @param string|null $authSource
     * @param string|null $owner
     * @param string[] $postLogoutRedirectUri
     * @param string|null $backChannelLogoutUri
     * @return ClientEntityInterface
     */
    public static function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        array $redirectUri,
        array $scopes,
        bool $isEnabled,
        bool $isConfidential = false,
        ?string $authSource = null,
        ?string $owner = null,
        array $postLogoutRedirectUri = [],
        ?string $backChannelLogoutUri = null
    ): ClientEntityInterface {
        $client = new self();

        $client->identifier = $id;
        $client->secret = $secret;
        $client->name = $name;
        $client->description = $description;
        $client->authSource = empty($authSource) ? null : $authSource;
        $client->redirectUri = $redirectUri;
        $client->scopes = $scopes;
        $client->isEnabled = $isEnabled;
        $client->isConfidential = $isConfidential;
        $client->owner = empty($owner) ? null : $owner;
        $client->postLogoutRedirectUri = $postLogoutRedirectUri;
        $client->backChannelLogoutUri = empty($backChannelLogoutUri) ? null : $backChannelLogoutUri;

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromState(array $state): self
    {
        $client = new self();

        if (
            !is_string($state['id']) ||
            !is_string($state['secret']) ||
            !is_string($state['name']) ||
            !is_string($state['redirect_uri']) ||
            !is_string($state['scopes'])
        ) {
            throw OidcServerException::serverError('Invalid Client Entity state');
        }

        $client->identifier = $state['id'];
        $client->secret = $state['secret'];
        $client->name = $state['name'];
        $client->description = (string)($state['description'] ?? '');
        $client->authSource = empty($state['auth_source']) ? null : (string)$state['auth_source'];

        /** @var string[] $redirectUris */
        $redirectUris = json_decode($state['redirect_uri'], true);
        $client->redirectUri = $redirectUris;

        /** @var string[] $scopes */
        $scopes = json_decode($state['scopes'], true);
        $client->scopes = $scopes;

        $client->isEnabled = (bool) $state['is_enabled'];
        $client->isConfidential = (bool) ($state['is_confidential'] ?? false);
        $client->owner = empty($state['owner']) ? null : (string)$state['owner'];

        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = json_decode((string)($state['post_logout_redirect_uri'] ?? "[]"), true);
        $client->postLogoutRedirectUri = $postLogoutRedirectUris;


        $client->backChannelLogoutUri = empty($state['backchannel_logout_uri']) ?
            null :
            (string)$state['backchannel_logout_uri'];

        return $client;
    }

    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'secret' => $this->getSecret(),
            'name' => $this->getName(),
            'description' => $this->getDescription(),
            'auth_source' => $this->getAuthSourceId(),
            'redirect_uri' => json_encode($this->getRedirectUri()),
            'scopes' => json_encode($this->getScopes()),
            'is_enabled' => (int) $this->isEnabled(),
            'is_confidential' => (int) $this->isConfidential(),
            'owner' => $this->getOwner(),
            'post_logout_redirect_uri' => json_encode($this->getPostLogoutRedirectUri()),
            'backchannel_logout_uri' => $this->getBackChannelLogoutUri(),

        ];
    }

    public function toArray(): array
    {
        return [
            'id' => $this->identifier,
            'secret' => $this->secret,
            'name' => $this->name,
            'description' => $this->description,
            'auth_source' => $this->authSource,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'is_enabled' => $this->isEnabled,
            'is_confidential' => $this->isConfidential,
            'owner' => $this->owner,
            'post_logout_redirect_uri' => $this->postLogoutRedirectUri,
            'backchannel_logout_uri' => $this->backChannelLogoutUri,
        ];
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function restoreSecret(string $secret): ClientEntityInterface
    {
        $this->secret = $secret;

        return $this;
    }

    public function getDescription(): string
    {
        return $this->description;
    }

    public function getAuthSourceId(): ?string
    {
        return $this->authSource;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function isEnabled(): bool
    {
        return $this->isEnabled;
    }

    public function getOwner(): ?string
    {
        return $this->owner;
    }

    public function getPostLogoutRedirectUri(): array
    {
        return $this->postLogoutRedirectUri ?? [];
    }

    public function setPostLogoutRedirectUri(array $postLogoutRedirectUri): void
    {
        $this->postLogoutRedirectUri = $postLogoutRedirectUri;
    }

    public function getBackChannelLogoutUri(): ?string
    {
        return $this->backChannelLogoutUri;
    }

    public function setBackChannelLogoutUri(?string $backChannelLogoutUri): void
    {
        $this->backChannelLogoutUri = $backChannelLogoutUri;
    }
}
