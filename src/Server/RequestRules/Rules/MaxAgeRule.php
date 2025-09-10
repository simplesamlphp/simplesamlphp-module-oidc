<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class MaxAgeRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthenticationService $authenticationService,
        private readonly SspBridge $sspBridge,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
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
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        if (!array_key_exists(ParamsEnum::MaxAge->value, $requestParams) || !$authSimple->isAuthenticated()) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        if (
            false === filter_var(
                $requestParams[ParamsEnum::MaxAge->value],
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 0]],
            )
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::MaxAge->value,
                'max_age must be a valid integer',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        $maxAge = (int) $requestParams[ParamsEnum::MaxAge->value];
        $lastAuth =  (int) $authSimple->getAuthData('AuthnInstant');
        $isExpired = $lastAuth + $maxAge < time();

        if ($isExpired) {
            unset($requestParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = $this->sspBridge->utils()->http()->addURLParameters(
                $this->sspBridge->utils()->http()->getSelfURLNoQuery(),
                $requestParams,
            );

            $this->authenticationService->authenticate($client, $loginParams);
        }

        return new Result($this->getKey(), $lastAuth);
    }
}
