<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;

/**
 * The client a token request redeeming a pre-authorized code was found to come from.
 *
 * Client authentication is optional for that grant, so a wallet which identified itself is one of two
 * things: a registered client the authentication resolver accepted, which the access token is then
 * issued to, or a non-registered wallet known only by the `client_id` it declared, which nothing can
 * authenticate and which the token is bound to instead. This carries that distinction from the rule
 * which draws it to the grant which acts on it, since the two need different things: the entity for
 * the one, the identifier for the other.
 */
class PreAuthorizedCodeClient
{
    /**
     * @param string $identifier The identifier the wallet is known by, which for a registered client is its own.
     * @param ?\SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $registeredClient The registered
     * client, or null for a wallet which only declared an identifier.
     */
    protected function __construct(
        protected readonly string $identifier,
        protected readonly ?ClientEntityInterface $registeredClient,
    ) {
    }


    /**
     * A registered client, authenticated by the credentials it presented or accepted as presented where
     * its registration allows it.
     */
    public static function registered(ClientEntityInterface $client): self
    {
        return new self($client->getIdentifier(), $client);
    }


    /**
     * A wallet which is not a registered client, known by the `client_id` it declared and nothing more.
     */
    public static function selfDeclared(string $identifier): self
    {
        return new self($identifier, null);
    }


    public function getIdentifier(): string
    {
        return $this->identifier;
    }


    public function getRegisteredClient(): ?ClientEntityInterface
    {
        return $this->registeredClient;
    }


    public function isRegistered(): bool
    {
        return $this->registeredClient !== null;
    }
}
