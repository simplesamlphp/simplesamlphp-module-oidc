<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

use RuntimeException;

/**
 * Raised by a token repository asked about a token it has no record of.
 *
 * A RuntimeException, as the repositories threw before, and its own class so that a caller can tell "no such
 * token" -- a verdict on the token -- from a storage failure, which a PDOException (a RuntimeException too)
 * reports.
 */
class TokenNotFoundException extends RuntimeException
{
}
