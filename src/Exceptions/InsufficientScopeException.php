<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised when a caller proved who it is and is not allowed to do this.
 *
 * Kept apart from a plain authorization failure because the two call for different answers. A request
 * whose token is missing or unrecognized should be told to authenticate, and a caller which reads that
 * as "my token is wrong" and rotates it would be right. A request whose token is perfectly good but
 * carries the wrong scopes must not be told that: retrying with a fresh token will not help, and the
 * fix is a configuration change rather than anything the caller can do at runtime.
 */
class InsufficientScopeException extends AuthorizationException
{
}
