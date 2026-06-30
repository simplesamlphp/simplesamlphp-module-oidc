<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
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
 * @extends AbstractRule<int>
 */
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
        $loggerService->debug('MaxAgeRule::checkRule');

        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $authSimple = $this->authSimpleFactory->build($client);

        // Determine the effective max_age: the request parameter takes precedence over the client's registered
        // default_max_age (OIDC DCR 1.0). When neither is present, max_age is not in effect.
        $effectiveMaxAge = null;
        if (array_key_exists(ParamsEnum::MaxAge->value, $requestParams)) {
            $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
            $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

            if (
                false === filter_var(
                    $requestParams[ParamsEnum::MaxAge->value],
                    FILTER_VALIDATE_INT,
                    ['options' => ['min_range' => 0]],
                )
            ) {
                $loggerService->notice(
                    'Authorization request rejected: `max_age` is not a valid non-negative integer.',
                    ['client_id' => $client->getIdentifier()],
                );
                throw OidcServerException::invalidRequest(
                    ParamsEnum::MaxAge->value,
                    'max_age must be a valid integer',
                    null,
                    $redirectUri,
                    $state,
                    $responseMode,
                );
            }

            $effectiveMaxAge = (int) $requestParams[ParamsEnum::MaxAge->value];
        } elseif ($client instanceof ClientEntityInterface) {
            $effectiveMaxAge = $client->getDefaultMaxAge();
        }

        // require_auth_time forces the auth_time claim into the ID Token even when no max_age is in effect.
        $requireAuthTime = $client instanceof ClientEntityInterface && $client->getRequireAuthTime();

        // Nothing to enforce or compute when neither an effective max_age nor require_auth_time applies, or when the
        // user is not (yet) authenticated (the normal authentication flow handles login in that case).
        if (($effectiveMaxAge === null && !$requireAuthTime) || !$authSimple->isAuthenticated()) {
            return null;
        }

        $lastAuth = (int) $authSimple->getAuthData('AuthnInstant');

        // Enforce re-authentication when the session is older than the effective max_age.
        if ($effectiveMaxAge !== null && ($lastAuth + $effectiveMaxAge < time())) {
            unset($requestParams['prompt']);
            $loginParams = [];
            $loginParams['ReturnTo'] = $this->sspBridge->utils()->http()->addURLParameters(
                $this->sspBridge->utils()->http()->getSelfURLNoQuery(),
                $requestParams,
            );

            $this->authenticationService->authenticateForClient($client, $loginParams);
        }

        // The result value becomes the ID Token auth_time (set by the grant), satisfying require_auth_time and/or
        // recording the authentication instant used for the max_age check.
        return new Result($this->getKey(), $lastAuth);
    }
}
