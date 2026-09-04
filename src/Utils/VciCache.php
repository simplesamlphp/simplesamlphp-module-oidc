<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\OpenID\Decorators\CacheDecorator;

/**
 * Cache for the Verifiable Credential Issuance layer.
 *
 * A type of its own, as with FederationCache and ProtocolCache, so the container can tell the three
 * apart. Its store is configured separately from theirs because what is kept here is fetched from
 * destinations named by whoever is being issued a credential, rather than by this deployment.
 *
 * The library namespaces its own keys, so more than one VCI consumer can share this without colliding.
 * Resolved DID documents are the first.
 */
class VciCache extends CacheDecorator
{
}
