<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised when a status is asked for which the target Status List can not represent.
 *
 * The number of bits per entry fixes the largest status a list can carry, and it can not be changed
 * for a list which already exists, so this is a permanent property of that list rather than something
 * a caller can retry past. A pool which needs to suspend has to be configured with enough bits before
 * its lists are created.
 */
class UnsupportedStatusException extends StatusListException
{
}
