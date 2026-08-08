<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

/**
 * Raised when a request carried no authorization token at all.
 *
 * Distinct from a token which was supplied and found wanting, because the challenge sent back differs.
 * RFC 6750 reserves the `invalid_token` error code for a token that actually arrived; answering a
 * request which carried none with that code tells a client its credentials were rejected, and a client
 * which believes that may rotate a token which was never the problem.
 */
class MissingTokenException extends AuthorizationException
{
}
