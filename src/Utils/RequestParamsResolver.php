<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;

/**
 * Resolve authorization params from HTTP request (based or not based on used method), and from Request Object param if
 * present.
 */
class RequestParamsResolver
{
    public function __construct(
        protected Helpers $helpers,
        protected Core $core,
    ) {
    }

    /**
     * Get all HTTP request params (not from Request Object).
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return array
     */
    public function getAllFromRequest(ServerRequestInterface $request): array
    {
        return $this->helpers->http()->getAllRequestParams($request);
    }

    /**
     * Get all HTTP request params based on allowed methods (not from Request Object).
     *
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @return array
     */
    public function getAllFromRequestBasedOnAllowedMethods(
        ServerRequestInterface $request,
        array $allowedMethods,
    ): array {
        return $this->helpers->http()->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            $allowedMethods,
        ) ?? [];
    }

    /**
     * Get all request params, including those from Request Object if present.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getAll(ServerRequestInterface $request): array
    {
        $requestParams = $this->getAllFromRequest($request);

        return array_merge(
            $requestParams,
            $this->resolveRequestObjectParams($requestParams),
        );
    }


    /**
     * Get all request params based on allowed methods, including those from Request Object if present.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getAllBasedOnAllowedMethods(
        ServerRequestInterface $request,
        array $allowedMethods,
    ): array {
        $requestParams = $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods);

        return array_merge(
            $requestParams,
            $this->resolveRequestObjectParams($requestParams),
        );
    }

    /**
     * Get param value from HTTP request or Request Object if present, based on allowed methods.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getBasedOnAllowedMethods(
        string $paramKey,
        ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): mixed {
        $allParams = $this->getAllBasedOnAllowedMethods($request, $allowedMethods);

        return $allParams[$paramKey] ?? null;
    }

    /**
     * Get param value as null or string from HTTP request or Request Object if present, based on allowed methods.
     * This is convenience method, since in most cases params will be strings (or absent).
     *
     * @param string $paramKey
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @return string|null
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getAsStringBasedOnAllowedMethods(
        string $paramKey,
        ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): ?string {
        /** @psalm-suppress MixedAssignment */
        return is_null($value = $this->getBasedOnAllowedMethods($paramKey, $request, $allowedMethods)) ?
        null :
        (string)$value;
    }

    /**
     * Get param value from HTTP request (not from Request Object), based on allowed methods.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     */
    public function getFromRequestBasedOnAllowedMethods(
        string $paramKey,
        ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): ?string {
        $allParams = $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods);

        return isset($allParams[$paramKey]) ? (string)$allParams[$paramKey] : null;
    }

    /**
     * Check if Request Object is present as request param and parse it to use its claims as params.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function resolveRequestObjectParams(array $requestParams): array
    {
        if (array_key_exists(ParamsEnum::Request->value, $requestParams)) {
            return $this->parseRequestObjectToken((string)$requestParams[ParamsEnum::Request->value])->getPayload();
        }

        return [];
    }

    /**
     * Parse the Request Object token. Note that this won't do any validation of it.
     *
     * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestParameterRule
     * @param string $token
     * @return \SimpleSAML\OpenID\Core\RequestObject
     */
    public function parseRequestObjectToken(string $token): Core\RequestObject
    {
        return $this->core->getRequestObjectFactory()->fromToken($token);
    }
}
