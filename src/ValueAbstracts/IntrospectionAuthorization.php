<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SimpleSAML\Module\oidc\Codebooks\IntrospectionCallerRoleEnum;

/**
 * Who an authenticated introspection caller is, and with it which tokens it is allowed to ask about.
 *
 * Authenticating successfully and being allowed to introspect a particular token are two different
 * things: RFC 7662 section 2.1 leaves it to the authorization server to decide whether the caller may
 * inspect the token it presented. This carries that decision from the point where the caller is
 * identified to the point where the token's owner becomes known, since the two are resolved apart.
 *
 * The caller's identity travels with it, whatever the role, because more than the owner check needs it:
 * a release decision made per caller, rate limiting by the identity of the resource server (AARC-G052
 * section 4), and the log lines which say who asked.
 */
class IntrospectionAuthorization
{
    /**
     * @param string $callerId The client identifier the caller authenticated as, or, on the administrative
     * path, who the administrator or API token stands for. Never an API token itself.
     */
    protected function __construct(
        protected readonly IntrospectionCallerRoleEnum $role,
        protected readonly string $callerId,
    ) {
    }


    /**
     * A client which authenticated as itself, and may therefore only see what was issued to it. That
     * tells it nothing it did not already hold, whereas another client's token would answer with that
     * token's subject, scopes and lifetime.
     */
    public static function forClient(string $clientId): self
    {
        return new self(IntrospectionCallerRoleEnum::Client, $clientId);
    }


    /**
     * A client the deployment has named as a resource server, trusted with every token this OP issued.
     */
    public static function forResourceServer(string $clientId): self
    {
        return new self(IntrospectionCallerRoleEnum::ResourceServer, $clientId);
    }


    /**
     * A client the deployment has named as the upstream hub, trusted with every token this OP issued.
     */
    public static function forUpstreamHub(string $clientId): self
    {
        return new self(IntrospectionCallerRoleEnum::UpstreamHub, $clientId);
    }


    /**
     * A logged in administrator, or an API token holding an introspection scope, trusted with every token
     * this OP issued.
     *
     * @param string $principal Who the caller stands for: see
     * {@see \SimpleSAML\Module\oidc\Services\Api\Authorization::requireCallerForAnyOfScope()}.
     */
    public static function forAdministrative(string $principal): self
    {
        return new self(IntrospectionCallerRoleEnum::Administrative, $principal);
    }


    /**
     * @param ?string $clientId The client a token was issued to, or null when that could not be established.
     */
    public function mayIntrospectTokenOf(?string $clientId): bool
    {
        if ($this->role !== IntrospectionCallerRoleEnum::Client) {
            return true;
        }

        // A token with no established owner is refused rather than shown: there is nothing to compare it
        // against, and this caller has not been trusted with anyone else's tokens.
        return $clientId !== null && $clientId === $this->callerId;
    }


    public function getRole(): IntrospectionCallerRoleEnum
    {
        return $this->role;
    }


    public function getCallerId(): string
    {
        return $this->callerId;
    }
}
