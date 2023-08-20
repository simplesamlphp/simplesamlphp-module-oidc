<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Error;
use Throwable;

class PromptRule extends AbstractRule
{
    private AuthSimpleFactory $authSimpleFactory;

    private AuthenticationService $authenticationService;

    public function __construct(
        AuthSimpleFactory $authSimpleFactory,
        AuthenticationService $authenticationService
    ) {
        $this->authSimpleFactory = $authSimpleFactory;
        $this->authenticationService = $authenticationService;
    }

    /**
     * @throws Error\AuthSource
     * @throws Error\BadRequest
     * @throws Error\Exception
     * @throws OAuthServerException
     * @throws Throwable
     * @throws OidcServerException
     * @throws Error\NotFound
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        $queryParams = $request->getQueryParams();
        if (!array_key_exists('prompt', $queryParams)) {
            return null;
        }

        $prompt = explode(" ", (string)$queryParams['prompt']);
        if (count($prompt) > 1 && in_array('none', $prompt, true)) {
            throw OAuthServerException::invalidRequest('prompt', 'Invalid prompt parameter');
        }
        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $state */
        $state = $queryParams['state'] ?? null;

        if (in_array('none', $prompt, true) && !$authSimple->isAuthenticated()) {
            throw OidcServerException::loginRequired(
                null,
                $redirectUri,
                null,
                $state,
                $useFragmentInHttpErrorResponses
            );
        }

        if (in_array('login', $prompt, true) && $authSimple->isAuthenticated()) {
            $queryParams = (new HTTP())->parseQueryString($request->getUri()->getQuery());
            unset($queryParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = (new HTTP())->addURLParameters((new HTTP())->getSelfURLNoQuery(), $queryParams);

            $this->authenticationService->getAuthenticateUser($request, $loginParams, true);
        }

        return null;
    }
}
