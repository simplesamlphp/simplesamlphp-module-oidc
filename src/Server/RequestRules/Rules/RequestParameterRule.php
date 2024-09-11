<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class RequestParameterRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        protected JwksResolver $jwksResolver,
    ) {
        parent::__construct($requestParamsResolver);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $requestParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Request->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($requestParam)) {
            return null;
        }

        // Request param exists. Check if the result bag already has request object resolved. This can happen if the
        // request object was used as a way to do automatic client registration in OpenID Federation.
        // @see ClientIdRule
        if ($currentResultBag->has($this->getKey())) {
            $loggerService->debug('Request object has already been resolved, skipping rule ' . $this->getKey());
            return null;
        }

        // There is no request object already resolved. We will do it now.
        $requestObject = $this->requestParamsResolver->parseRequestObjectToken($requestParam);

        // If request object is not protected (signed), we are allowed to use it as is.
        if (!$requestObject->isProtected()) {
            return new Result($this->getKey(), $requestObject->getPayload());
        }

        // It is protected, we must validate it.

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $stateValue */
        $stateValue = ($currentResultBag->get(StateRule::class))?->getValue();

        ($jwks = $this->jwksResolver->forClient($client)) || throw OidcServerException::accessDenied(
            'can not validate request object, client JWKS not available',
            $redirectUri,
            null,
            $stateValue,
            $useFragmentInHttpErrorResponses,
        );

        try {
            $requestObject->verifyWithKeySet($jwks);
        } catch (\Throwable $exception) {
            throw OidcServerException::accessDenied(
                'request object validation failed: ' . $exception->getMessage(),
                $redirectUri,
                null,
                $stateValue,
                $useFragmentInHttpErrorResponses,
            );
        }

        return new Result($this->getKey(), $requestObject->getPayload());
    }
}
