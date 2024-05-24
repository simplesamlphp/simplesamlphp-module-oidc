<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Error;
use Throwable;

class MaxAgeRule extends AbstractRule
{
    public function __construct(
        private readonly AuthSimpleFactory $authSimpleFactory,
        private readonly AuthenticationService $authenticationService,
    ) {
    }

    /**
     * @throws Error\AuthSource
     * @throws Throwable
     * @throws Error\BadRequest
     * @throws OidcServerException
     * @throws Error\NotFound
     * @throws Error\Exception
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET'],
    ): ?ResultInterface {
        $queryParams = $request->getQueryParams();

        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        if (!array_key_exists('max_age', $queryParams) || !$authSimple->isAuthenticated()) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $state */
        $state = $queryParams['state'] ?? null;

        if (false === filter_var($queryParams['max_age'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]])) {
            throw OidcServerException::invalidRequest(
                'max_age',
                'max_age must be a valid integer',
                null,
                $redirectUri,
                $state,
                $useFragmentInHttpErrorResponses,
            );
        }

        $maxAge = (int) $queryParams['max_age'];
        $lastAuth =  (int) $authSimple->getAuthData('AuthnInstant');
        $isExpired = $lastAuth + $maxAge < time();

        if ($isExpired) {
            $queryParams = (new HTTP())->parseQueryString($request->getUri()->getQuery());
            unset($queryParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = (new HTTP())->addURLParameters((new HTTP())->getSelfURLNoQuery(), $queryParams);

            $this->authenticationService->getAuthenticateUser($request, $loginParams, true);
        }

        return new Result($this->getKey(), $lastAuth);
    }
}
