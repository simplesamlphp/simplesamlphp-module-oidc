<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;

class ResourceServer
{
    public function __construct(
        protected readonly BearerTokenValidator $bearerTokenValidator,
    ) {
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validateAuthenticatedRequest(ServerRequestInterface $request): ServerRequestInterface
    {
        return $this->bearerTokenValidator->validateAuthorization($request);
    }
}
