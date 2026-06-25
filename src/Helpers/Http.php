<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class Http
{
    public function getAllRequestParams(ServerRequestInterface $request): array
    {
        return array_merge(
            $request->getQueryParams(),
            (is_array($parsedBody = $request->getParsedBody()) ? $parsedBody : []),
        );
    }

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

        if (! in_array($requestMethod, $allowedMethods, true)) {
            return null;
        }

        return match ($requestMethod) {
            HttpMethodsEnum::GET => $request->getQueryParams(),
            HTTPMethodsEnum::POST => is_array($parsedBody = $request->getParsedBody()) ? $parsedBody : null,
            default => null,
        };
    }

    /**
     * Extract a Bearer token from an Authorization header value (RFC 6750,
     * Section 2.1), or null if no (non-empty) Bearer token is present. The
     * "Bearer" scheme is matched case-insensitively.
     *
     * This operates on the raw header string (rather than a request object) so
     * it can be used uniformly regardless of the HTTP request abstraction in
     * use (PSR-7 ServerRequestInterface, Symfony HttpFoundation Request, ...).
     * Callers pass the header value, e.g. PSR `$request->getHeaderLine('Authorization')`
     * or Symfony `$request->headers->get('Authorization')`.
     */
    public function getBearerToken(?string $authorizationHeaderValue): ?string
    {
        if ($authorizationHeaderValue === null) {
            return null;
        }

        if (preg_match('/^Bearer\s+(.+)$/i', $authorizationHeaderValue, $matches) !== 1) {
            return null;
        }

        $token = trim($matches[1]);

        return $token === '' ? null : $token;
    }
}
