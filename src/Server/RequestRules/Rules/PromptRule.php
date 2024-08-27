<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\Utils\HTTP;

class PromptRule extends AbstractRule
{
    public function __construct(
        ParamsResolver $paramsResolver,
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthenticationService $authenticationService,
    ) {
        parent::__construct($paramsResolver);
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
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
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        $requestParams = $this->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        ) ?? [];
        if (!array_key_exists('prompt', $requestParams)) {
            return null;
        }

        $prompt = explode(" ", (string)$requestParams['prompt']);
        if (count($prompt) > 1 && in_array('none', $prompt, true)) {
            throw OAuthServerException::invalidRequest('prompt', 'Invalid prompt parameter');
        }
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        if (in_array('none', $prompt, true) && !$authSimple->isAuthenticated()) {
            throw OidcServerException::loginRequired(
                null,
                $redirectUri,
                null,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        if (in_array('login', $prompt, true) && $authSimple->isAuthenticated()) {
            unset($requestParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = (new HTTP())
                ->addURLParameters((new HTTP())->getSelfURLNoQuery(), $requestParams);

            $this->authenticationService->authenticate($request, $loginParams);
        }

        return null;
    }
}
