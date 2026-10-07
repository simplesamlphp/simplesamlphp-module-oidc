<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use JsonException;
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
use SimpleSAML\OpenID\Core\ClientAssertion;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\RequestObject;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Resolve authorization params from an HTTP request (based or not based on
 * a used method), from Request Object param if present, and from Request URI
 * param (Pushed Authorization Request or Request Object by reference) if
 * present. A Pushed Authorization Request is redeemed with its pushed params
 * only, see resolveParams().
 */
class RequestParamsResolver
{
    /**
     * The request attribute an endpoint which takes no authorization requests
     * (the token and the end session endpoints) sets on the PSR-7 request it
     * hands on: the params of that request are then read as they were sent,
     * with no Request Object (request param) or request_uri resolved into
     * them. Only the authorization request has those, so they are parameters
     * such an endpoint does not recognize, which it ignores (RFC 6749 section
     * 3.2 has the token endpoint do so): one sent there neither adds params
     * nor takes any away. A request without it is read as an authorization
     * request.
     */
    public const string ATTRIBUTE_OWN_PARAMS_ONLY = 'oidc_own_params_only';


    /**
     * Request Object Bags parsed from a Request Object JWT passed by value
     * (request param), keyed by token.
     *
     * @var array<string, ?\SimpleSAML\OpenID\RequestObject\RequestObjectBag>
     */
    protected array $requestObjectBagsByToken = [];

    /**
     * Request Object Bags fetched and parsed from a https Request URI passed
     * by reference (request_uri param), keyed by request_uri value.
     *
     * @var array<string, ?\SimpleSAML\OpenID\RequestObject\RequestObjectBag>
     */
    protected array $requestObjectBagsByUri = [];

    /**
     * Params resolved from Pushed Authorization Request URIs (urn form),
     * keyed by request_uri value.
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
        return $this->resolveParams($request, $this->getAllFromRequest($request));
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
        return $this->resolveParams(
            $request,
            $this->getAllFromRequestBasedOnAllowedMethods($request, $allowedMethods),
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
     * Assemble the authorization request params from the HTTP request params,
     * or leave them as they are for a request marked with
     * ATTRIBUTE_OWN_PARAMS_ONLY.
     *
     * A Request Object, passed by value or by an https Request URI, complements
     * the HTTP request params, its claims superseding params of the same name,
     * the way OpenID Connect Core has it.
     *
     * A Pushed Authorization Request URI (urn form) does not: the request is the
     * pushed one. RFC 9126 section 4 has it built as RFC 9101 defines, whose
     * sections 5 and 6.3 have the authorization server use only the params of
     * the Request Object, even where the client repeats them in the query. So
     * of the HTTP request params, only client_id and request_uri are kept,
     * which RequestUriRule needs to find the pushed request and to check that
     * the client pushed it. Any other param sent with the request_uri is
     * ignored, so one the client did not push can not be added to the request
     * on the way through the user agent.
     *
     * @return mixed[]
     */
    protected function resolveParams(Request|ServerRequestInterface $request, array $requestParams): array
    {
        if (
            $request instanceof ServerRequestInterface &&
            $request->getAttribute(self::ATTRIBUTE_OWN_PARAMS_ONLY) === true
        ) {
            return $requestParams;
        }

        /** @psalm-suppress MixedAssignment */
        $requestUri = $requestParams[ParamsEnum::RequestUri->value] ?? null;

        // Whatever else the request carries: one which also carries the request
        // param is refused by RequestUriRule, which reads the raw params.
        if (
            is_string($requestUri) &&
            str_starts_with($requestUri, PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX)
        ) {
            return array_merge(
                array_intersect_key(
                    $requestParams,
                    [ParamsEnum::ClientId->value => true, ParamsEnum::RequestUri->value => true],
                ),
                $this->resolvePushedAuthorizationRequestParams($requestUri),
            );
        }

        return array_merge(
            $requestParams,
            $this->resolveRequestObjectParams($requestParams),
            $this->resolveRequestUriParams($requestParams),
        );
    }


    /**
     * Check if Request Object is present as a request param (passed by value)
     * and parse it to use its claims as params.
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

        // Use the OpenID Connect Core flavor for (unverified) param resolution,
        // since it is the most lenient one (signature validation and policy
        // checks are done in RequestObjectRule).
        return $this->parseRequestObjectBagByToken($token)?->get(Core\RequestObject::class)?->getPayload() ?? [];
    }


    /**
     * Check if an https Request URI is present as a request param and resolve
     * its claims to use them as params: the Request Object is fetched and
     * parsed (if allowed by policy), but note that this won't do signature
     * validation of it, nor any policy checks like one-time use or expiration.
     * A Pushed Authorization Request URI (urn form) is redeemed by
     * resolveParams() before this is reached.
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

        // Using both request and request_uri params is not allowed. Don't
        // resolve anything and let the caller produce the proper error.
        if (array_key_exists(ParamsEnum::Request->value, $requestParams)) {
            return [];
        }

        // https Request URI (by reference): fetch and parse the Request Object
        // (if allowed by policy).
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
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error resolving pushed authorization request: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return $this->pushedAuthorizationRequestParams[$requestUri] = [];
        }
    }


    /**
     * Resolve the Request Object Bag for the current request, regardless of
     * whether the Request Object was passed by value (request param) or by
     * reference (https request_uri param). For Pushed Authorization Request
     * URIs (urn form) this returns null, since PAR carries previously pushed
     * params, not a Request Object. Note that this won't do signature
     * validation; that is done in RequestObjectRule.
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
     * Parse (memoized) the Request Object token using all available Request
     * Object flavors (OpenID Connect Core, JAR, OpenID Federation). The
     * returned bag contains an entry for every flavor for which the
     * token parsed and passed flavor-specific validation, so it can
     * be used to differentiate between, for example, OpenID Connect
     * Core Request Objects (which can be unsigned) and JAR Request
     * Objects (which must be signed). Note that this won't do
     * signature validation.
     */
    protected function parseRequestObjectBagByToken(string $token): ?RequestObjectBag
    {
        if (!array_key_exists($token, $this->requestObjectBagsByToken)) {
            try {
                $this->requestObjectBagsByToken[$token] = $this->requestObject->requestObjectParser()
                    ->fromToken($token);
            } catch (Throwable $throwable) {
                $this->loggerService->warning(
                    'RequestParamsResolver: error parsing request object: ' . $throwable->getMessage(),
                );
                $this->requestObjectBagsByToken[$token] = null;
            }
        }

        return $this->requestObjectBagsByToken[$token];
    }


    /**
     * Fetch and parse (memoized) the Request Object from the given https
     * Request URI, if allowed by policy.
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
                    $this->moduleConfig->getRequestUriFetchTimeout(),
                    $this->moduleConfig->getRequestUriMaxSizeBytes(),
                );
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'RequestParamsResolver: error fetching request object from request_uri: ' . $throwable->getMessage(),
                compact('requestUri'),
            );
            return $this->requestObjectBagsByUri[$requestUri] = null;
        }
    }


    /**
     * Decide whether a https Request URI (Request Object by reference) is
     * allowed to be fetched. This is the single authorization point for
     * outbound Request Object fetches (SSRF / DoS surface):
     *  - the OP must support the request_uri parameter (request_uri_parameter_supported),
     *  - for registered (non-federation) clients, the request_uri must be
     *    pre-registered in the client's request_uris (RFC 9126 exact-matching),
     *  - for clients not in storage or registered through OpenID Federation,
     *    fetching is allowed when federation is enabled and the request_uri
     *    is allowed by the federation request_uri prefix allowlist
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

        // Client not in storage or registered through OpenID Federation:
        // federation by-reference path.
        return $this->moduleConfig->getFederationEnabled() &&
        $this->isFederationRequestUriAllowed($requestUri);
    }


    /**
     * Check the federation request_uri against the configured prefix allowlist
     * (SSRF / DoS mitigation for the outbound fetch of a not-yet-trusted
     * federation candidate's Request Object).
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
    public function parseClientAssertionToken(string $clientAssertionParam): ClientAssertion
    {
        return $this->core->clientAssertionFactory()->fromToken($clientAssertionParam);
    }


    /**
     * Whether this is an OpenID4VCI authorization code request, which, unlike an OpenID Connect one, need not
     * carry the openid scope. It is one only while Verifiable Credential issuance is enabled, for response_type
     * "code", and when the request carries something only that flow asks for:
     *  - an issuer_state, which a wallet takes from a Credential Offer (OpenID4VCI 1.0 section 5.1.3);
     *  - a scope which is a credential configuration id, the way a wallet starts the flow on its own;
     *  - authorization_details with an entry of type openid_credential (OpenID4VCI 1.0 section 5.1.1).
     *
     * None of the three is validated here. Each is only a claim the request makes, and the rules which own the
     * parameters decide whether it holds. None is cast to a string either, so a parameter sent as an array
     * (issuer_state[]=...) is not read as the string "Array".
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function isVciAuthorizationCodeRequest(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): bool {
        if (!$this->isVciCodeRequest($request, $allowedMethods)) {
            return false;
        }

        return $this->hasIssuerState($request, $allowedMethods) ||
        $this->hasVciScope($request, $allowedMethods) ||
        $this->hasOpenIdCredentialAuthorizationDetails($request, $allowedMethods);
    }


    /**
     * Whether this is an OpenID4VCI authorization code request carrying an issuer_state, that is one which says
     * it follows a Credential Offer. The issuer_state value is not checked here.
     *
     * This is the narrower of the two detections. It is what lets a client which is not registered fall back to
     * the generic VCI client, when that is allowed, so a wallet starting the flow on its own does not qualify.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function isVciAuthorizationCodeRequestWithIssuerState(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): bool {
        return $this->isVciCodeRequest($request, $allowedMethods) &&
        $this->hasIssuerState($request, $allowedMethods);
    }


    /**
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function isVciCodeRequest(Request|ServerRequestInterface $request, array $allowedMethods): bool
    {
        return $this->moduleConfig->getVciEnabled() &&
        $this->getBasedOnAllowedMethods(ParamsEnum::ResponseType->value, $request, $allowedMethods) === 'code';
    }


    /**
     * Any scalar counts, since IssuerStateRule reads the value as a string and a request object may carry a
     * number.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function hasIssuerState(Request|ServerRequestInterface $request, array $allowedMethods): bool
    {
        return is_scalar(
            $this->getBasedOnAllowedMethods(ParamsEnum::IssuerState->value, $request, $allowedMethods),
        );
    }


    /**
     * The scope is split the way ScopeRule splits it, and matched against the scopes issuance adds, which are the
     * credential configuration ids.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function hasVciScope(Request|ServerRequestInterface $request, array $allowedMethods): bool
    {
        $scopeParam = $this->getBasedOnAllowedMethods(ParamsEnum::Scope->value, $request, $allowedMethods);

        if (!is_string($scopeParam)) {
            return false;
        }

        $vciScopes = array_map('strval', array_keys($this->moduleConfig->getVciScopes()));

        return array_intersect($this->helpers->str()->convertScopesStringToArray($scopeParam), $vciScopes) !== [];
    }


    /**
     * Read the way AuthorizationDetailsRule reads it: the serialized JSON of a query or form parameter, or the
     * decoded array a Request Object claim holds (RFC 9396 section 3).
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function hasOpenIdCredentialAuthorizationDetails(
        Request|ServerRequestInterface $request,
        array $allowedMethods,
    ): bool {
        /** @psalm-suppress MixedAssignment */
        $authorizationDetails = $this->getBasedOnAllowedMethods(
            ParamsEnum::AuthorizationDetails->value,
            $request,
            $allowedMethods,
        );

        if (is_string($authorizationDetails)) {
            try {
                /** @psalm-suppress MixedAssignment */
                $authorizationDetails = json_decode($authorizationDetails, true, 512, JSON_THROW_ON_ERROR);
            } catch (JsonException) {
                return false;
            }
        }

        if (!is_array($authorizationDetails)) {
            return false;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($authorizationDetails as $authorizationDetail) {
            if (is_array($authorizationDetail) && ($authorizationDetail['type'] ?? null) === 'openid_credential') {
                return true;
            }
        }

        return false;
    }
}
