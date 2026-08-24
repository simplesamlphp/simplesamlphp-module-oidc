<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Contracts;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\StatusList\Values\StatusAllocation;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;

/**
 * Claims an index in a Status List for a credential about to be issued.
 *
 * This lives in the module rather than in the openid library on purpose. What indices are handed out,
 * where they are recorded and when a list is replaced are properties of an application's storage and
 * lifecycle, not invariants of the specification; the library keeps to the latter.
 *
 * Claiming the index and recording what it was claimed for are one operation, so there is never a
 * moment where an index is taken but nothing says by whom. The credential identifier therefore has to
 * be minted before allocation rather than after it.
 */
interface StatusIndexAllocatorInterface
{
    /**
     * @param \SimpleSAML\Module\oidc\StatusList\Values\StatusListPool $pool Policy the credential's
     * configuration allocates under.
     * @param string $credentialId Identifier the credential will carry as its `jti`, minted beforehand.
     * @param string $credentialConfigurationId Recorded on the entry, since a pool serves several
     * configurations and the pool alone does not say which one this was.
     * @param ?string $subjectRef Keyed hash of the user identifier, never the identifier itself.
     * @param ?\DateTimeImmutable $expiresAt When the credential expires, or null if it never does. A
     * list holding a non-expiring entry can never be retired.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException When no index could be claimed in
     * any list. Running out of probes in one list is not this: that rotates to a new list and retries.
     */
    public function allocateFor(
        StatusListPool $pool,
        string $credentialId,
        string $credentialConfigurationId,
        ?string $subjectRef = null,
        ?DateTimeImmutable $expiresAt = null,
    ): StatusAllocation;
}
