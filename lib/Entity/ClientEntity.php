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

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;

class ClientEntity implements ClientEntityInterface, MementoInterface
{
    use EntityTrait;
    use ClientTrait;

    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $description;

    /**
     * @var string
     */
    private $authSource;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var bool
     */
    private $isEnabled;


    /**
     * Constructor
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
     * @param string $authSource
     * @param array $redirectUri
     * @param array $scopes
     * @param bool $isEnabled
     * @return self
     */
    public static function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        string $authSource,
        array $redirectUri,
        array $scopes,
        bool $isEnabled
    ): self {
        $client = new self();

        $client->identifier = $id;
        $client->secret = $secret;
        $client->name = $name;
        $client->description = $description;
        $client->authSource = $authSource;
        $client->redirectUri = $redirectUri;
        $client->scopes = $scopes;
        $client->isEnabled = $isEnabled;

        return $client;
    }


    /**
     * {@inheritdoc}
     */
    public static function fromState(array $state)
    {
        $client = new self();

        $client->identifier = $state['id'];
        $client->secret = $state['secret'];
        $client->name = $state['name'];
        $client->description = $state['description'];
        $client->authSource = $state['auth_source'];
        $client->redirectUri = json_decode($state['redirect_uri'], true);
        $client->scopes = json_decode($state['scopes'], true);
        $client->isEnabled = (bool) $state['is_enabled'];

        return $client;
    }


    /**
     * {@inheritdoc}
     */
    public function getState(): array
    {
        return [
            'id' => $this->identifier,
            'secret' => $this->secret,
            'name' => $this->name,
            'description' => $this->description,
            'auth_source' => $this->authSource,
            'redirect_uri' => json_encode($this->redirectUri),
            'scopes' => json_encode($this->scopes),
            'is_enabled' => $this->isEnabled ? 1 : 0,
        ];
    }


    /**
     * @return array
     */
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
        ];
    }


    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }


    /**
     * @param string $secret
     * @return self
     */
    public function restoreSecret(string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }


    /**
     * @return string
     */
    public function getDescription(): string
    {
        return $this->description;
    }


    /**
     * @return string
     */
    public function getAuthSource(): string
    {
        return $this->authSource;
    }


    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }


    /**
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->isEnabled;
    }
}
