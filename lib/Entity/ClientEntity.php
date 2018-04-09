<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
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

    private function __construct()
    {
    }

    public static function fromData(
        string $id,
        string $secret,
        string $name,
        string $description,
        string $authSource,
        array $redirectUri,
        array $scopes
    ): self {
        $client = new self();

        $client->identifier = $id;
        $client->secret = $secret;
        $client->name = $name;
        $client->description = $description;
        $client->authSource = $authSource;
        $client->redirectUri = $redirectUri;
        $client->scopes = $scopes;

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
        ];
    }

    /**
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

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
}
