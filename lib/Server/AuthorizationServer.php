<?php

namespace SimpleSAML\Module\oidc\Server;

use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use LogicException;
use SimpleSAML\Error\BadRequest;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithCheckerResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\UiLocalesRule;
use Throwable;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    protected ClientRepositoryInterface $clientRepository;

    protected RequestRulesManager $requestRulesManager;

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
            throw new LogicException('Can not validate request (no RequestRulesManager defined)');
        }
        $this->requestRulesManager = $requestRulesManager;
    }

    /**
     * @inheritDoc
     * @throws BadRequest|Throwable
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
            $reason = sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        // state and redirectUri is used here so we can return HTTP redirect error in case of invalid response_type.
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        $redirectUri = $resultBag->getOrFail(RedirectUriRule::class)->getValue();

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

    /**
     * @throws Throwable
     * @throws BadRequest
     */
    public function validateLogoutRequest(ServerRequestInterface $request): LogoutRequest
    {
        $rulesToExecute = [
            StateRule::class,
            IdTokenHintRule::class,
            PostLogoutRedirectUriRule::class,
            UiLocalesRule::class,
        ];

        try {
            $resultBag = $this->requestRulesManager->check($request, $rulesToExecute, false, ['GET', 'POST']);
        } catch (OidcServerException $exception) {
            $reason = sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        /** @var UnencryptedToken|null $idTokenHint */
        $idTokenHint = $resultBag->getOrFail(IdTokenHintRule::class)->getValue();
        /** @var string|null $postLogoutRedirectUri */
        $postLogoutRedirectUri = $resultBag->getOrFail(PostLogoutRedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        /** @var string|null $uiLocales */
        $uiLocales = $resultBag->getOrFail(UiLocalesRule::class)->getValue();

        return new LogoutRequest($idTokenHint, $postLogoutRedirectUri, $state, $uiLocales);
    }
}
