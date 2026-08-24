<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

/**
 * Which tokens an authenticated introspection caller is allowed to ask about.
 *
 * Authenticating successfully and being allowed to introspect a particular token are two different
 * things: RFC 7662 section 2.1 leaves it to the authorization server to decide whether the caller may
 * inspect the token it presented. This carries that decision from the point where the caller is
 * identified to the point where the token's owner becomes known, since the two are resolved apart.
 */
class IntrospectionAuthorization
{
    /**
     * @param ?string $clientId The only client whose tokens may be introspected, or null for any of them.
     */
    protected function __construct(
        protected readonly ?string $clientId,
    ) {
    }


    /**
     * A caller trusted with every token this OP has issued: a logged in administrator, an API token
     * holding an introspection scope, or a client the deployment has named as a resource server.
     */
    public static function forAnyToken(): self
    {
        return new self(null);
    }


    /**
     * A client which authenticated as itself, and may therefore only see what was issued to it. That
     * tells it nothing it did not already hold, whereas another client's token would answer with that
     * token's subject, scopes and lifetime.
     */
    public static function forTokensOfClient(string $clientId): self
    {
        return new self($clientId);
    }


    /**
     * @param ?string $clientId The client a token was issued to, or null when that could not be established.
     */
    public function mayIntrospectTokenOf(?string $clientId): bool
    {
        if ($this->clientId === null) {
            return true;
        }

        // A token with no established owner is refused rather than shown: there is nothing to compare it
        // against, and this caller has not been trusted with anyone else's tokens.
        return $clientId !== null && $clientId === $this->clientId;
    }


    /**
     * The client this caller is limited to, or null when it is limited to none.
     */
    public function getClientId(): ?string
    {
        return $this->clientId;
    }
}
