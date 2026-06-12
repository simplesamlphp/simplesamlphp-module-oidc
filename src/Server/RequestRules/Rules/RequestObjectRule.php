<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Core\RequestObject as ConnectRequestObject;
use SimpleSAML\OpenID\Jar\RequestObject as JarRequestObject;

class RequestObjectRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected JwksResolver $jwksResolver,
        protected ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $loggerService->debug('RequestObjectRule::checkRule');

        // A Request Object can be passed by value (request param) or by reference (https request_uri param).
        // Either way, the parsing/fetching is done by the RequestParamsResolver; here we only need to know
        // whether such a Request Object is present for this request.
        if (!$this->hasRequestObjectSource($request, $allowedServerRequestMethods)) {
            return null;
        }

        // Request object is present. Check if the result bag already has a request object resolved. This can
        // happen if the request object was used as a way to do automatic client registration in OpenID
        // Federation.
        // @see ClientRule::resolveFromFederation()
        if ($currentResultBag->has($this->getKey())) {
            $loggerService->debug('Request object has already been resolved, skipping rule ' . $this->getKey());
            return null;
        }

        // Parse it using all available Request Object flavors, so we can differentiate between OpenID Connect
        // Core Request Objects (which can be unsigned) and JAR Request Objects (which must be signed).
        $requestObjectBag = $this->requestParamsResolver->getRequestObjectBag($request, $allowedServerRequestMethods);

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        /** @var ?string $stateValue */
        $stateValue = ($currentResultBag->get(StateRule::class))?->getValue();

        // The Request Object source is present, but it could not be parsed (by value) or fetched/parsed (by
        // reference). Note that for the by-reference case, RequestUriRule would normally reject this earlier.
        if ($requestObjectBag === null) {
            throw OidcServerException::invalidRequest(
                'request',
                'Request object could not be parsed or fetched.',
                null,
                $redirectUri,
                $stateValue,
                $responseMode,
            );
        }

        if (!$this->isOidcAuthorizationRequest($request, $allowedServerRequestMethods)) {
            // This is a plain OAuth 2.0 authorization request, so JAR
            // (RFC 9101) rules apply: the Request Object must be a signed JWT
            // containing the Client ID claim.
            $jarRequestObject = $requestObjectBag->get(JarRequestObject::class);
            if (!$jarRequestObject instanceof JarRequestObject) {
                throw OidcServerException::invalidRequest(
                    'request',
                    'Request object is not a valid JAR Request Object (note that it must be signed).',
                    null,
                    $redirectUri,
                    $stateValue,
                    $responseMode,
                );
            }

            if ($jarRequestObject->getClientId() !== $client->getIdentifier()) {
                throw OidcServerException::invalidRequest(
                    'request',
                    'Client ID claim in request object does not match the client_id parameter.',
                    null,
                    $redirectUri,
                    $stateValue,
                    $responseMode,
                );
            }

            $this->verifySignature($jarRequestObject, $client, $redirectUri, $stateValue, $responseMode);

            return new Result($this->getKey(), $jarRequestObject->getPayload());
        }

        // This is an OpenID Connect authorization request, so OpenID Connect
        // Core rules apply: the Request Object can be unsigned
        // (unless policy requires signature).
        $requestObject = $requestObjectBag->get(ConnectRequestObject::class);
        if (!$requestObject instanceof ConnectRequestObject) {
            throw OidcServerException::invalidRequest(
                'request',
                'Request object is not a valid Request Object.',
                null,
                $redirectUri,
                $stateValue,
                $responseMode,
            );
        }

        // If request object is not protected (signed), check if signature is required.
        if (!$requestObject->isProtected()) {
            $requireSigned = $this->moduleConfig->getRequireSignedRequestObject() ||
            $client->getRequireSignedRequestObject();
            if ($requireSigned) {
                throw OidcServerException::invalidRequest(
                    'request',
                    'Request object must be signed (alg: none is not allowed).',
                    null,
                    $redirectUri,
                    $stateValue,
                    $responseMode,
                );
            }
            return new Result($this->getKey(), $requestObject->getPayload());
        }

        // It is protected, we must validate it.
        $this->verifySignature($requestObject, $client, $redirectUri, $stateValue, $responseMode);

        return new Result($this->getKey(), $requestObject->getPayload());
    }

    /**
     * Check whether the request carries a Request Object, either by value (request param) or by reference
     * (https request_uri param). Note that a Pushed Authorization Request URI (urn form) is not a Request
     * Object source (it carries previously pushed params, handled by RequestUriRule).
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    protected function hasRequestObjectSource(
        ServerRequestInterface $request,
        array $allowedServerRequestMethods,
    ): bool {
        if (
            !is_null($this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
                ParamsEnum::Request->value,
                $request,
                $allowedServerRequestMethods,
            ))
        ) {
            return true;
        }

        $requestUri = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::RequestUri->value,
            $request,
            $allowedServerRequestMethods,
        );

        return is_string($requestUri) && str_starts_with(strtolower($requestUri), 'https://');
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function verifySignature(
        ConnectRequestObject|JarRequestObject $requestObject,
        ClientEntityInterface $client,
        string $redirectUri,
        ?string $stateValue,
        ResponseModeInterface $responseMode,
    ): void {
        ($jwks = $this->jwksResolver->forClient($client)) || throw OidcServerException::accessDenied(
            'can not validate request object, client JWKS not available',
            $redirectUri,
            null,
            $stateValue,
            $responseMode,
        );

        try {
            $requestObject->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw OidcServerException::accessDenied(
                'request object validation failed: ' . $exception->getMessage(),
                $redirectUri,
                null,
                $stateValue,
                $responseMode,
            );
        }
    }
}
