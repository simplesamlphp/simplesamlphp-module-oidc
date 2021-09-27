<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Session;
use SimpleSAML\Utils\HTTP;

class MaxAgeRule extends AbstractRule
{
    private const MAX_AGE_REAUTHENTICATE = 'max_age_reauthenticate';

    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;
    /**
     * @var SessionService
     */
    private $sessionService;
    /**
     * @var AuthenticationService
     */
    private $authenticationService;

    public function __construct(
        AuthSimpleFactory $authSimpleFactory,
        SessionService $sessionService,
        AuthenticationService $authenticationService
    ) {
        $this->authSimpleFactory = $authSimpleFactory;
        $this->sessionService = $sessionService;
        $this->authenticationService = $authenticationService;
    }

    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $queryParams = $request->getQueryParams();

        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        $this->sessionService->setIsLogoutHandlerDisabled(false);

        if (!array_key_exists('max_age', $queryParams) || !$authSimple->isAuthenticated()) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();

        if (false === filter_var($queryParams['max_age'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]])) {
            throw OidcServerException::invalidRequest(
                'max_age',
                'max_age must be a valid integer',
                null,
                $redirectUri,
                $queryParams['state'] ?? null,
                $useFragmentInHttpErrorResponses
            );
        }

        $maxAge = (int) $queryParams['max_age'];
        $lastAuth =  (int) $authSimple->getAuthData('AuthnInstant');
        $isExpired = $lastAuth + $maxAge < time();

        if ($isExpired) {
            $queryParams = HTTP::parseQueryString($request->getUri()->getQuery());
            unset($queryParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = HTTP::addURLParameters(HTTP::getSelfURLNoQuery(), $queryParams);

            $this->sessionService->setIsLogoutHandlerDisabled(true);
            $this->authenticationService->getAuthenticateUser($request, $loginParams, true);
        }

        return new Result($this->getKey(), $lastAuth);
    }
}
