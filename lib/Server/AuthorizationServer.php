<?php

namespace SimpleSAML\Module\oidc\Server;

use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use SimpleSAML\Error\BadRequest;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithCheckerResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    /**
     * @var ClientRepositoryInterface
     */
    protected $clientRepository;

    /**
     * @var RequestRulesManager
     */
    protected $requestRulesManager;

    /**
     * @inheritDoc
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        $privateKey,
        $encryptionKey,
        ResponseTypeInterface $responseType = null,
        RequestRulesManager $requestRulesManager = null
    ) {
        parent::__construct(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey,
            $responseType
        );

        $this->clientRepository = $clientRepository;

        if ($requestRulesManager === null) {
            throw new \LogicException('Can not validate request (no RequestRulesManager defined)');
        }
        $this->requestRulesManager = $requestRulesManager;
    }

    /**
     * @inheritDoc
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        $rulesToExecute = [
            StateRule::class,
            ClientIdRule::class,
            RedirectUriRule::class
        ];

        try {
            $resultBag = $this->requestRulesManager->check($request, $rulesToExecute);
        } catch (OidcServerException $exception) {
            $reason = \sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        // state and redirectUri is used here so we can return HTTP redirect error in case of invalid response_type.
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        $redirectUri = $resultBag->getOrFail(RedirectUriRule::class)->getValue();

        // TODO mivanci acr-values
        // * check for acr_values request parameter and make it available in authZ request
        // * consider saving acr_values parameter for authZ request in DB
        // * check if required acr value is essential or voluntary, and depending on authN performed return appropriate
        // acr claim in ID token, or error out if required ACR is not possible
        // * indicate if authentication was performed based on cookie (user had active session) or auth source was used

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                if (! $grantType instanceof AuthorizationValidatableWithCheckerResultBagInterface) {
                    throw OidcServerException::serverError('grant type must be validatable with already validated ' .
                                                           'result bag');
                }

                return $grantType->validateAuthorizationRequestWithCheckerResultBag($request, $resultBag);
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
    }
}
