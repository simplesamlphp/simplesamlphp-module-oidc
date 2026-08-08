<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised by the module's Token Status List storage and lifecycle handling.
 *
 * Distinct from \SimpleSAML\OpenID\Exceptions\StatusListException, which the openid library raises for
 * violations of the specification itself. This one covers what is this module's own concern: storage,
 * allocation, publication and the surrounding lifecycle.
 */
class StatusListException extends OidcException
{
}
