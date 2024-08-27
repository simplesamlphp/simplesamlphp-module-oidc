<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\Utils\HTTP;

class MaxAgeRule extends AbstractRule
{
    public function __construct(
        ParamsResolver $paramsResolver,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthenticationService $authenticationService,
    ) {
        parent::__construct($paramsResolver);
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
        $requestParams = $this->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        ) ?? [];

        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        if (!array_key_exists('max_age', $requestParams) || !$authSimple->isAuthenticated()) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        if (
            false === filter_var(
                $requestParams['max_age'],
                FILTER_VALIDATE_INT,
                ['options' => ['min_range' => 0]],
            )
        ) {
            throw OidcServerException::invalidRequest(
                'max_age',
                'max_age must be a valid integer',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        $maxAge = (int) $requestParams['max_age'];
        $lastAuth =  (int) $authSimple->getAuthData('AuthnInstant');
        $isExpired = $lastAuth + $maxAge < time();

        if ($isExpired) {
            unset($requestParams['prompt']);
            $loginParams = [];
            // TODO mivanci Move to SspBridge
            $loginParams['ReturnTo'] = (new HTTP())
                ->addURLParameters((new HTTP())->getSelfURLNoQuery(), $requestParams);

            $this->authenticationService->authenticate($request, $loginParams);
        }

        return new Result($this->getKey(), $lastAuth);
    }
}
