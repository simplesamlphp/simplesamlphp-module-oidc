<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\RequestObject;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use Symfony\Component\HttpFoundation\Request;

/**
 * Resolve authorization params from an HTTP request (based or not based on
 * a used method), from Request Object param if present, and from Request URI
 * param (Pushed Authorization Request or Request Object by reference) if
 * present.
 */
class RequestParamsResolver
{
    /**
     * Resolved request_uri params, keyed by request_uri value.
     *
     * @var array<string, mixed[]>
     */
    protected array $resolvedRequestUriParams = [];

    /**
     * Request Object Bags resolved from (fetched) https request_uri values,
     * keyed by request_uri value.
     *
     * @var array<string, ?\SimpleSAML\OpenID\RequestObject\RequestObjectBag>
     */
    protected array $resolvedRequestUriBags = [];

    public function __construct(
        protected readonly Helpers $helpers,
        protected readonly Core $core,
        protected readonly Federation $federation,
        protected readonly PsrHttpBridge $psrHttpBridge,
        protected readonly RequestObject $requestObject,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly ClientRepository $clientRepository,
        protected readonly PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * Get all HTTP request params (not from Request Object).
     *
     * @return mixed[]
     */
    public function getAllFromRequest(Request|ServerRequestInterface $request): array
    {
        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

        return $this->helpers->http()->getAllRequestParams($request);
    }

    /**
     * Get all HTTP request params based on allowed methods (not from
     * Request Object).
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @return mixed[]
     */
    public function getAllFromRequestBasedOnAllowedMethods(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): array {
        if ($request instanceof Request) {
            $request = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);
        }

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
    public function getAll(Request|ServerRequestInterface $request): array
    {
        $requestParams = $this->getAllFromRequest($request);

        return array_merge(
            $requestParams,
            $this->resolveRequestObjectParams($requestParams),
            $this->resolveRequestUriParams($requestParams),
        );
    }


    /**
     * Get all request params based on allowed methods, including those from
     * Request Object if present.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getAllBasedOnAllowedMethods(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): array {
        $requestParams = $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods);

        return array_merge(
            $requestParams,
            $this->resolveRequestObjectParams($requestParams),
            $this->resolveRequestUriParams($requestParams),
        );
    }

    /**
     * Get param value from an HTTP request or Request Object if present.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function get(string $paramKey, Request|ServerRequestInterface $request): mixed
    {
        return $this->getAll($request)[$paramKey] ?? null;
    }

    /**
     * Get param value from an HTTP request or Request Object if present,
     * based on allowed methods.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getBasedOnAllowedMethods(
        string $paramKey,
        Request|ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): mixed {
        $allParams = $this->getAllBasedOnAllowedMethods($request, $allowedMethods);
        return $allParams[$paramKey] ?? null;
    }

    /**
     * Get param value as null or string from an HTTP request or Request Object
     * if present, based on allowed methods. This is a convenience method,
     * since in most cases params will be strings (or absent).
     *
     * @param string $paramKey
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @return string|null
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function getAsStringBasedOnAllowedMethods(
        string $paramKey,
        Request|ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): ?string {
        /** @psalm-suppress MixedAssignment */
        return is_null($value = $this->getBasedOnAllowedMethods($paramKey, $request, $allowedMethods)) ?
        null :
        (string)$value;
    }

    /**
     * Get param value from an HTTP request (not from Request Object), based
     * on allowed methods.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     */
    public function getFromRequestBasedOnAllowedMethods(
        string $paramKey,
        Request|ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): ?string {
        $allParams = $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods);

        return isset($allParams[$paramKey]) ? (string)$allParams[$paramKey] : null;
    }

    /**
     * Check if Request Object is present as a request param and parse it to
     * use its claims as params.
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
     * Check if Request URI is present as a request param and resolve its
     * claims to use them as params. For Pushed Authorization Request URIs
     * (urn form), params are resolved from the previously pushed (validated)
     * authorization request. For https Request URIs, the Request Object is
     * fetched and parsed, but note that this won't do signature validation
     * of it, nor any policy checks like one-time use or expiration.
     *
     * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule
     * @return mixed[]
     */
    protected function resolveRequestUriParams(array $requestParams): array
    {
        if (
            (!array_key_exists(ParamsEnum::RequestUri->value, $requestParams)) ||
            (!is_string($requestUri = $requestParams[ParamsEnum::RequestUri->value])) ||
            ($requestUri === '')
        ) {
            return [];
        }

        // Using both request and request_uri params is not allowed. Don't resolve anything and let the
        // RequestUriRule produce the proper error.
        if (array_key_exists(ParamsEnum::Request->value, $requestParams)) {
            return [];
        }

        if (array_key_exists($requestUri, $this->resolvedRequestUriParams)) {
            return $this->resolvedRequestUriParams[$requestUri];
        }

        if (str_starts_with($requestUri, PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX)) {
            return $this->resolvedRequestUriParams[$requestUri] =
            $this->resolvePushedAuthorizationRequestParams($requestUri);
        }

        if (str_starts_with(strtolower($requestUri), 'https://')) {
            return $this->resolvedRequestUriParams[$requestUri] =
            $this->resolveHttpsRequestUriParams($requestUri, $requestParams);
        }

        return $this->resolvedRequestUriParams[$requestUri] = [];
    }

    /**
     * @return mixed[]
     */
    protected function resolvePushedAuthorizationRequestParams(string $requestUri): array
    {
        try {
            return $this->pushedAuthorizationRequestRepository->findValid($requestUri)?->getParameters() ?? [];
        } catch (\Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error resolving pushed authorization request: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return [];
        }
    }

    /**
     * Fetch the Request Object from the https Request URI and use its claims as params. The Request URI must be
     * registered for the client resolved from the client_id request param (it is fetched only in that case).
     *
     * @return mixed[]
     */
    protected function resolveHttpsRequestUriParams(string $requestUri, array $requestParams): array
    {
        $this->resolvedRequestUriBags[$requestUri] = null;

        if (
            (!array_key_exists(ParamsEnum::ClientId->value, $requestParams)) ||
            (!is_string($clientId = $requestParams[ParamsEnum::ClientId->value])) ||
            ($clientId === '')
        ) {
            return [];
        }

        $client = $this->clientRepository->getClientEntity($clientId);
        if (
            (!$client instanceof ClientEntityInterface) ||
            (!in_array($requestUri, $client->getRequestUris(), true))
        ) {
            return [];
        }

        try {
            $requestObjectBag = $this->requestObject->requestObjectParser()->fromRequestUri(
                $requestUri,
                $this->moduleConfig->getRequestUriTimeout(),
                $this->moduleConfig->getRequestUriMaxSizeBytes(),
            );
        } catch (\Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error fetching request object from request_uri: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return [];
        }

        $this->resolvedRequestUriBags[$requestUri] = $requestObjectBag;

        // Use the OpenID Connect Core flavor for (unverified) param resolution, since it is the most lenient
        // one (signature validation and policy checks are handled in RequestUriRule).
        return $requestObjectBag->get(Core\RequestObject::class)?->getPayload() ?? [];
    }

    /**
     * Get the Request Object Bag resolved from the given (fetched) https request_uri value, if any.
     */
    public function getResolvedRequestUriBag(string $requestUri): ?RequestObjectBag
    {
        return $this->resolvedRequestUriBags[$requestUri] ?? null;
    }

    /**
     * Parse the Request Object token according to OpenID Core specification.
     * Note that this won't do signature validation of it.
     *
     * @param string $token
     * @return \SimpleSAML\OpenID\Core\RequestObject
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule
     */
    public function parseRequestObjectToken(string $token): Core\RequestObject
    {
        return $this->core->requestObjectFactory()->fromToken($token);
    }

    /**
     * Parse the Request Object token using all available Request Object flavors (OpenID Connect Core, JAR,
     * OpenID Federation). The returned bag contains an entry for every flavor for which the token parsed and
     * passed flavor-specific validation, so it can be used to differentiate between, for example, OpenID
     * Connect Core Request Objects (which can be unsigned) and JAR Request Objects (which must be signed).
     * Note that this won't do signature validation.
     */
    public function parseRequestObjectBag(string $token): RequestObjectBag
    {
        return $this->requestObject->requestObjectParser()->fromToken($token);
    }

    /**
     * Parse the Request Object token according to OpenID Federation
     * specification. Note that this won't do signature validation of it.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\RequestObjectException
     */
    public function parseFederationRequestObjectToken(string $token): Federation\RequestObject
    {
        return $this->federation->requestObjectFactory()->fromToken($token);
    }

    /**
     * Parse the Client Assertion token according to OpenID Core specification.
     * Note that this won't do signature validation of it.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function parseClientAssertionToken(string $clientAssertionParam): Core\ClientAssertion
    {
        return $this->core->clientAssertionFactory()->fromToken($clientAssertionParam);
    }

    /**
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function isVciAuthorizationCodeRequest(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): bool {
        return
            // Only applies to VCI Authorization Code flow.
        $this->getAsStringBasedOnAllowedMethods(
            ParamsEnum::ResponseType->value,
            $request,
            $allowedMethods,
        ) === 'code' &&
            // Issuer State is only used for VCI Authorization Code flow requests, so use it as a form of detection.
        is_string($this->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IssuerState->value,
            $request,
            $allowedMethods,
        ));
    }
}
