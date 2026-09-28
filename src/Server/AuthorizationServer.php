<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server;

use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface as OAuth2AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @psalm-suppress PropertyNotSetInConstructor
 */
class AuthorizationServer extends OAuth2AuthorizationServer
{
    /** @psalm-suppress PossiblyUnusedProperty Private property in parent. */
    protected ClientRepositoryInterface $clientRepository;

    protected RequestRulesManager $requestRulesManager;

    /**
     * @var \League\OAuth2\Server\CryptKeyInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected CryptKeyInterface $publicKey;


    /**
     * @inheritDoc
     */
    public function __construct(
        ClientRepositoryInterface $clientRepository,
        AccessTokenRepositoryInterface $accessTokenRepository,
        ScopeRepositoryInterface $scopeRepository,
        CryptKey|string $privateKey,
        Key|string $encryptionKey,
        ?ResponseTypeInterface $responseType = null,
        ?RequestRulesManager $requestRulesManager = null,
        protected readonly ?LoggerService $loggerService = null,
        protected readonly ?PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository = null,
    ) {
        parent::__construct(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKey,
            $encryptionKey,
            $responseType,
        );

        $this->clientRepository = $clientRepository;

        if ($requestRulesManager === null) {
            throw new LogicException('Can not validate request (no RequestRulesManager defined)');
        }
        $this->requestRulesManager = $requestRulesManager;
    }


    /**
     * @inheritDoc
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequestInterface
    {
        $this->loggerService?->debug('AuthorizationServer::validateAuthorizationRequest');

        $rulesToExecute = [
            StateRule::class,
            ClientRule::class,
            RequestUriRule::class,
            ClientRedirectUriRule::class,
            ResponseModeRule::class,
        ];

        try {
            $resultBag = $this->requestRulesManager->check(
                $request,
                $rulesToExecute,
                new QueryResponseMode(),
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            );
        } catch (OidcServerException $exception) {
            $reason = sprintf(
                "AuthorizationServer: %s %s",
                $exception->getMessage(),
                $exception->getHint() ?? '',
            );
            $this->loggerService?->error($reason);
            throw new BadRequest($reason);
        }

        $this->loggerService?->debug(
            'AuthorizationServer: Result bag validated',
            ['rulesToExecute' => $rulesToExecute],
        );

        // state and redirectUri is used here, so we can return HTTP redirect error in case of invalid response_type.
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        $redirectUri = $resultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $responseMode = $resultBag->getOrFail(ResponseModeRule::class)->getValue();

        foreach ($this->enabledGrantTypes as $grantType) {
            $this->loggerService?->debug(
                'AuthorizationServer: Checking if grant type can respond to authorization request: ' .
                $grantType::class,
            );
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                $this->loggerService?->debug(
                    'AuthorizationServer: Grant type can respond to authorization request: ' .
                    $grantType::class,
                );

                if (! $grantType instanceof AuthorizationValidatableWithRequestRules) {
                    $this->loggerService?->error(
                        'AuthorizationServer: grant type must be validatable with ' .
                        'already validated result bag: ' . $grantType::class,
                    );
                    throw OidcServerException::serverError('grant type must be validatable with already validated ' .
                                                           'result bag');
                }

                $this->loggerService?->debug(
                    sprintf(
                        'AuthorizationServer: Grant type class: %s, identifier: %s ',
                        $grantType::class,
                        $grantType->getIdentifier(),
                    ),
                );

                $authorizationRequest = $grantType->validateAuthorizationRequestWithRequestRules($request, $resultBag);
                $this->bindPushedAuthorizationRequestUri($authorizationRequest, $resultBag);

                return $authorizationRequest;
            } else {
                $this->loggerService?->debug(
                    'AuthorizationServer: Grant type can NOT respond to ' .
                    'authorization request: ' . $grantType::class,
                );
            }
        }

        $this->loggerService?->error(
            'AuthorizationServer: Not a single registered grant type can respond to authorization ' .
            'request.',
            ['requestQueryParams' => $request->getQueryParams()],
        );
        throw OidcServerException::unsupportedResponseType($redirectUri, $state, $responseMode);
    }


    /**
     * Consume the Pushed Authorization Request the request was made with, if any, before the grant issues the
     * authorization response.
     *
     * A PAR request_uri is one-time use (RFC 9126 section 4), but it can not be consumed when the request is
     * validated: the user agent comes back to the authorization endpoint with the same request_uri after the
     * login, and that request is validated again. RFC 9126 allows a request_uri to be used more than once that
     * way. It is consumed here instead, atomically, so one request_uri still yields at most one response, and a
     * second one, from another tab or a replay, is refused the way RequestUriRule refuses a consumed one.
     *
     * @inheritDoc
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function completeAuthorizationRequest(
        OAuth2AuthorizationRequestInterface $authRequest,
        ResponseInterface $response,
    ): ResponseInterface {
        if ($authRequest instanceof AuthorizationRequest) {
            $this->consumePushedAuthorizationRequest($authRequest);
        }

        return parent::completeAuthorizationRequest($authRequest, $response);
    }


    /**
     * Carry the PAR request_uri, if the request was made with one, on the validated authorization request,
     * which is what survives the login and the authprocs. A request of another type could not carry it, and
     * its PAR could then never be consumed, so it is refused.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function bindPushedAuthorizationRequestUri(
        OAuth2AuthorizationRequestInterface $authorizationRequest,
        ResultBagInterface $resultBag,
    ): void {
        $requestUri = $resultBag->get(RequestUriRule::class)?->getValue();

        if (
            !is_string($requestUri) ||
            !str_starts_with($requestUri, PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX)
        ) {
            return;
        }

        if (!$authorizationRequest instanceof AuthorizationRequest) {
            $this->loggerService?->error(
                'AuthorizationServer: pushed authorization request can not be tracked for one-time use.',
                ['authorizationRequestType' => $authorizationRequest::class],
            );
            throw OidcServerException::serverError('Pushed authorization request can not be tracked.');
        }

        $authorizationRequest->setPushedAuthorizationRequestUri($requestUri);
    }


    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function consumePushedAuthorizationRequest(AuthorizationRequest $authorizationRequest): void
    {
        $requestUri = $authorizationRequest->getPushedAuthorizationRequestUri();

        if ($requestUri === null) {
            return;
        }

        if ($this->pushedAuthorizationRequestRepository === null) {
            $this->loggerService?->error(
                'AuthorizationServer: no pushed authorization request repository to consume the request with.',
                compact('requestUri'),
            );
            throw OidcServerException::serverError('Pushed authorization request can not be consumed.');
        }

        if (!$this->pushedAuthorizationRequestRepository->consume($requestUri)) {
            $this->loggerService?->warning(
                'AuthorizationServer: pushed authorization request replay attempt.',
                compact('requestUri'),
            );
            throw new BadRequest('AuthorizationServer: Pushed authorization request has already been used.');
        }
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
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
            $resultBag = $this->requestRulesManager->check(
                $request,
                $rulesToExecute,
                new QueryResponseMode(),
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            );
        } catch (OidcServerException $exception) {
            $reason = sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        $idTokenHint = $resultBag->getOrFail(IdTokenHintRule::class)->getValue();
        $postLogoutRedirectUri = $resultBag->getOrFail(PostLogoutRedirectUriRule::class)->getValue();
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        $uiLocales = $resultBag->getOrFail(UiLocalesRule::class)->getValue();

        return new LogoutRequest($idTokenHint, $postLogoutRedirectUri, $state, $uiLocales);
    }
}
