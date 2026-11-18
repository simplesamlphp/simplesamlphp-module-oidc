<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised when client authentication failed, which RFC 6749 section 5.2 answers with `invalid_client`: credentials
 * were presented and refused, the client authenticated by a method the endpoint does not take, or the request
 * included no client authentication at all.
 *
 * Distinct from a refused API token, which is no client's credential: telling a client which got its secret wrong
 * that an API token was refused sends whoever reads the answer to the wrong configuration.
 */
class InvalidClientException extends AuthorizationException
{
}
