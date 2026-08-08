<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised when a status change kept losing to concurrent changes of the same entry.
 *
 * Distinct from the entry simply already holding the requested status, which is a no-op and not an
 * error. Here the entry ended up holding something the caller did not ask for, so reporting success
 * would tell an administrator a credential was revoked when it was not.
 */
class StatusConflictException extends StatusListException
{
}
