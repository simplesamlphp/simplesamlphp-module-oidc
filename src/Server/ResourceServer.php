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
     * @param string $resourceUrl The URL this OP publishes for the protected resource the request came to, which
     * the `htu` of a DPoP proof has to name. League's validator interface takes the request alone, so it goes in a
     * request attribute.
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function validateAuthenticatedRequest(
        ServerRequestInterface $request,
        string $resourceUrl,
    ): ServerRequestInterface {
        return $this->bearerTokenValidator->validateAuthorization(
            $request->withAttribute(BearerTokenValidator::ATTRIBUTE_RESOURCE_URL, $resourceUrl),
        );
    }
}
