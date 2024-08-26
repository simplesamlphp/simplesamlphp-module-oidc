<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;

/**
 * Resolve authorization params from HTTP request (based or not based on used method), and from request object param if
 * present.
 */
class AuthorizationParamsResolver
{
    public function __construct(
        protected Helpers $helpers,
    ) {
    }

    /**
     * Get all HTTP request parameters, and those from request object if present.
     *
     */
    public function getAll(ServerRequestInterface $request): array
    {
        return $this->helpers->http()->getAllRequestParams($request);
    }
}
