<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
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
     * Request Object Bags parsed from a Request Object JWT passed by value (request param), keyed by token.
     *
     * @var array<string, ?\SimpleSAML\OpenID\RequestObject\RequestObjectBag>
     */
    protected array $requestObjectBagsByToken = [];

    /**
     * Request Object Bags fetched and parsed from an https Request URI passed by reference (request_uri param),
     * keyed by request_uri value.
     *
     * @var array<string, ?\SimpleSAML\OpenID\RequestObject\RequestObjectBag>
     */
    protected array $requestObjectBagsByUri = [];

    /**
     * Params resolved from Pushed Authorization Request URIs (urn form), keyed by request_uri value.
     *
     * @var array<string, mixed[]>
     */
    protected array $pushedAuthorizationRequestParams = [];

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
     * Check if Request Object is present as a request param (passed by value) and parse it to use its claims
     * as params.
     *
     * @return mixed[]
     */
    protected function resolveRequestObjectParams(array $requestParams): array
    {
        if (
            (!array_key_exists(ParamsEnum::Request->value, $requestParams)) ||
            (!is_string($token = $requestParams[ParamsEnum::Request->value])) ||
            ($token === '')
        ) {
            return [];
        }

        // Use the OpenID Connect Core flavor for (unverified) param resolution, since it is the most lenient
        // one (signature validation and policy checks are done in RequestObjectRule).
        return $this->parseRequestObjectBagByToken($token)?->get(Core\RequestObject::class)?->getPayload() ?? [];
    }

    /**
     * Check if Request URI is present as a request param and resolve its claims to use them as params. For
     * Pushed Authorization Request URIs (urn form), params are resolved from the previously pushed (validated)
     * authorization request. For https Request URIs, the Request Object is fetched and parsed (if allowed by
     * policy), but note that this won't do signature validation of it, nor any policy checks like one-time use
     * or expiration.
     *
     * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule
     * @see \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule
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

        // Pushed Authorization Request URI (urn form): resolve from the previously pushed (validated) params.
        if (str_starts_with($requestUri, PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX)) {
            return $this->resolvePushedAuthorizationRequestParams($requestUri);
        }

        // https Request URI (by reference): fetch and parse the Request Object (if allowed by policy).
        return $this->fetchRequestObjectBagByUri($requestUri, $requestParams)
            ?->get(Core\RequestObject::class)?->getPayload() ?? [];
    }

    /**
     * @return mixed[]
     */
    protected function resolvePushedAuthorizationRequestParams(string $requestUri): array
    {
        if (array_key_exists($requestUri, $this->pushedAuthorizationRequestParams)) {
            return $this->pushedAuthorizationRequestParams[$requestUri];
        }

        try {
            return $this->pushedAuthorizationRequestParams[$requestUri] =
            $this->pushedAuthorizationRequestRepository->findValid($requestUri)?->getParameters() ?? [];
        } catch (\Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error resolving pushed authorization request: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return $this->pushedAuthorizationRequestParams[$requestUri] = [];
        }
    }

    /**
     * Resolve the Request Object Bag for the current request, regardless of whether the Request Object was
     * passed by value (request param) or by reference (https request_uri param). For Pushed Authorization
     * Request URIs (urn form) this returns null, since PAR carries previously pushed params, not a Request
     * Object. Note that this won't do signature validation; that is done in RequestObjectRule.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     */
    public function getRequestObjectBag(
        Request|ServerRequestInterface $request,
        array $allowedMethods = [HttpMethodsEnum::GET],
    ): ?RequestObjectBag {
        $requestParams = $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods);

        /** @psalm-suppress MixedAssignment */
        if (
            array_key_exists(ParamsEnum::Request->value, $requestParams) &&
            is_string($token = $requestParams[ParamsEnum::Request->value]) &&
            $token !== ''
        ) {
            return $this->parseRequestObjectBagByToken($token);
        }

        /** @psalm-suppress MixedAssignment */
        if (
            array_key_exists(ParamsEnum::RequestUri->value, $requestParams) &&
            is_string($requestUri = $requestParams[ParamsEnum::RequestUri->value]) &&
            str_starts_with(strtolower($requestUri), 'https://')
        ) {
            return $this->fetchRequestObjectBagByUri($requestUri, $requestParams);
        }

        return null;
    }

    /**
     * Parse (memoized) the Request Object token using all available Request Object flavors (OpenID Connect
     * Core, JAR, OpenID Federation). The returned bag contains an entry for every flavor for which the token
     * parsed and passed flavor-specific validation, so it can be used to differentiate between, for example,
     * OpenID Connect Core Request Objects (which can be unsigned) and JAR Request Objects (which must be
     * signed). Note that this won't do signature validation.
     */
    protected function parseRequestObjectBagByToken(string $token): ?RequestObjectBag
    {
        if (!array_key_exists($token, $this->requestObjectBagsByToken)) {
            try {
                $this->requestObjectBagsByToken[$token] = $this->requestObject->requestObjectParser()
                    ->fromToken($token);
            } catch (\Throwable $throwable) {
                $this->loggerService->warning(
                    'RequestParamsResolver: error parsing request object: ' . $throwable->getMessage(),
                );
                $this->requestObjectBagsByToken[$token] = null;
            }
        }

        return $this->requestObjectBagsByToken[$token];
    }

    /**
     * Fetch and parse (memoized) the Request Object from the given https Request URI, if allowed by policy.
     */
    protected function fetchRequestObjectBagByUri(string $requestUri, array $requestParams): ?RequestObjectBag
    {
        if (array_key_exists($requestUri, $this->requestObjectBagsByUri)) {
            return $this->requestObjectBagsByUri[$requestUri];
        }

        if (!$this->isHttpsRequestUriFetchAllowed($requestUri, $requestParams)) {
            return $this->requestObjectBagsByUri[$requestUri] = null;
        }

        try {
            return $this->requestObjectBagsByUri[$requestUri] = $this->requestObject->requestObjectParser()
                ->fromRequestUri(
                    $requestUri,
                    $this->moduleConfig->getRequestUriTimeout(),
                    $this->moduleConfig->getRequestUriMaxSizeBytes(),
                );
        } catch (\Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error fetching request object from request_uri: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return $this->requestObjectBagsByUri[$requestUri] = null;
        }
    }

    /**
     * Decide whether an https Request URI (Request Object by reference) is allowed to be fetched. This is the
     * single authorization point for outbound Request Object fetches (SSRF / DoS surface):
     *  - the OP must support the request_uri parameter (request_uri_parameter_supported),
     *  - for registered (non-federation) clients, the request_uri must be pre-registered in the client's
     *    request_uris (RFC 9126 exact-matching),
     *  - for clients not in storage or registered through OpenID Federation, fetching is allowed when
     *    federation is enabled and the request_uri is allowed by the federation request_uri prefix allowlist
     *    (trust is validated after the fetch, in ClientRule).
     */
    protected function isHttpsRequestUriFetchAllowed(string $requestUri, array $requestParams): bool
    {
        if (!$this->moduleConfig->getRequestUriParameterSupported()) {
            return false;
        }

        if (
            (!array_key_exists(ParamsEnum::ClientId->value, $requestParams)) ||
            (!is_string($clientId = $requestParams[ParamsEnum::ClientId->value])) ||
            ($clientId === '')
        ) {
            return false;
        }

        $client = $this->clientRepository->getClientEntity($clientId);

        if (
            $client instanceof ClientEntityInterface &&
            $client->getRegistrationType() !== RegistrationTypeEnum::FederatedAutomatic
        ) {
            return in_array($requestUri, $client->getRequestUris(), true);
        }

        // Client not in storage, or registered through OpenID Federation: federation by-reference path.
        return $this->moduleConfig->getFederationEnabled() &&
        $this->isFederationRequestUriAllowed($requestUri);
    }

    /**
     * Check the federation request_uri against the configured prefix allowlist (SSRF / DoS mitigation for the
     * outbound fetch of a not-yet-trusted federation candidate's Request Object).
     */
    protected function isFederationRequestUriAllowed(string $requestUri): bool
    {
        $allowedPrefixes = $this->moduleConfig->getFederationRequestUriAllowedPrefixes();

        // Null means explicitly allow any request_uri.
        if (is_null($allowedPrefixes)) {
            return true;
        }

        foreach ($allowedPrefixes as $allowedPrefix) {
            if ($allowedPrefix !== '' && str_starts_with($requestUri, $allowedPrefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse the Request Object token according to OpenID Core specification.
     * Note that this won't do signature validation of it.
     *
     * @param string $token
     * @return \SimpleSAML\OpenID\Core\RequestObject
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function parseRequestObjectToken(string $token): Core\RequestObject
    {
        return $this->core->requestObjectFactory()->fromToken($token);
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
