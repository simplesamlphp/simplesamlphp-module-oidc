<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class Http
{
    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @return ?array
     */
    public function getAllRequestParamsBasedOnAllowedMethods(
        ServerRequestInterface $request,
        array $allowedMethods,
    ): ?array {
        $requestMethod = HttpMethodsEnum::from(strtoupper($request->getMethod()));

        if (! in_array($requestMethod, $allowedMethods)) {
            return null;
        }

        return match ($requestMethod) {
            HttpMethodsEnum::GET => $request->getQueryParams(),
            HTTPMethodsEnum::POST => is_array($parsedBody = $request->getParsedBody()) ? $parsedBody : null,
            default => null,
        };
    }
}
