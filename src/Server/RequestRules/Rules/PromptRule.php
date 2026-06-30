<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * This rule never yields a value into the result bag (it only performs validation / side effects),
 * so its value type is `never`.
 *
 * @extends AbstractRule<never>
 */
class PromptRule extends AbstractRule
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
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Error\AuthSource
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
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
    ): ?Result {
        $loggerService->debug('PromptRule::checkRule');

        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

//        $requestParams = $this->getAllRequestParamsBasedOnAllowedMethods(
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );
        if (!array_key_exists(ParamsEnum::Prompt->value, $requestParams)) {
            return null;
        }

        $prompt = explode(" ", (string)$requestParams[ParamsEnum::Prompt->value]);
        if (count($prompt) > 1 && in_array('none', $prompt, true)) {
            $loggerService->notice(
                'Authorization request rejected: `prompt=none` cannot be combined with other prompt values.',
                ['client_id' => $client->getIdentifier(), 'prompt' => $requestParams[ParamsEnum::Prompt->value]],
            );
            throw OAuthServerException::invalidRequest(ParamsEnum::Prompt->value, 'Invalid prompt parameter');
        }
        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        if (in_array('none', $prompt, true) && !$authSimple->isAuthenticated()) {
            $loggerService->notice(
                'Authorization request rejected: `prompt=none` was requested but the user is not authenticated.',
                ['client_id' => $client->getIdentifier()],
            );
            throw OidcServerException::loginRequired(
                null,
                $redirectUri,
                null,
                $state,
                $responseMode,
            );
        }

        if (in_array('login', $prompt, true) && $authSimple->isAuthenticated()) {
            unset($requestParams[ParamsEnum::Prompt->value]);
            $loginParams = [];
            $loginParams['ReturnTo'] = $this->sspBridge->utils()->http()->addURLParameters(
                $this->sspBridge->utils()->http()->getSelfURLNoQuery(),
                $requestParams,
            );

            $this->authenticationService->authenticateForClient($client, $loginParams);
        }

        return null;
    }
}
