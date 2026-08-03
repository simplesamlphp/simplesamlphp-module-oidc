<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use SimpleSAML\OpenID\TokenStatusList\StatusReference;

/**
 * The outcome of claiming an index for a credential.
 *
 * Carries two things which look redundant and are not. The reference is what goes into the credential:
 * the URI as the allocator minted and stored it, plus the index, exactly as a Relying Party will use
 * them. The list ID is the storage key, which is what every later operation on this entry -- revoking
 * it, republishing the list -- needs. Resolving one from the other would mean mapping a URI back to a
 * row, which buys nothing and breaks the moment a deployment's base URL changes.
 */
class StatusAllocation
{
    public function __construct(
        protected readonly string $statusListId,
        protected readonly StatusReference $statusReference,
    ) {
    }

    public function getStatusListId(): string
    {
        return $this->statusListId;
    }

    /**
     * The reference as the credential carries it, for the `status` claim.
     */
    public function getStatusReference(): StatusReference
    {
        return $this->statusReference;
    }

    public function getUri(): string
    {
        return $this->statusReference->getUri();
    }

    public function getIdx(): int
    {
        return $this->statusReference->getIdx();
    }
}
