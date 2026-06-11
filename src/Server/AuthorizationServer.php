<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server;

use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\RequestObject;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    /** @psalm-suppress PossiblyUnusedProperty Private property in parent. */
    protected ClientRepositoryInterface $clientRepository;

    protected RequestRulesManager $requestRulesManager;

    protected ?PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository = null;
    protected ?RequestParamsResolver $requestParamsResolver = null;
    protected ?JwksResolver $jwksResolver = null;
    protected ?RequestObject $requestObject = null;
    protected ?ModuleConfig $moduleConfig = null;

    /**
     * @var \League\OAuth2\Server\CryptKey
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $publicKey;

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
        ?PushedAuthorizationRequestRepository $pushedAuthorizationRequestRepository = null,
        ?RequestParamsResolver $requestParamsResolver = null,
        ?JwksResolver $jwksResolver = null,
        ?RequestObject $requestObject = null,
        ?ModuleConfig $moduleConfig = null,
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

        $this->pushedAuthorizationRequestRepository = $pushedAuthorizationRequestRepository;
        $this->requestParamsResolver = $requestParamsResolver;
        $this->jwksResolver = $jwksResolver;
        $this->requestObject = $requestObject;
        $this->moduleConfig = $moduleConfig;
    }

    /**
     * @inheritDoc
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        $this->loggerService?->debug('AuthorizationServer::validateAuthorizationRequest');

        try {
            $queryParams = $request->getQueryParams();
            $bodyParams = $request->getParsedBody();
            $params = array_merge($queryParams, is_array($bodyParams) ? $bodyParams : []);

            $requestUri = isset($params['request_uri']) && is_string($params['request_uri']) ?
            $params['request_uri'] :
            null;
            $parRequestUri = null;

            if (is_string($requestUri) && $requestUri !== '') {
                if (str_starts_with($requestUri, 'urn:ietf:params:oauth:request_uri:')) {
                    if ($this->pushedAuthorizationRequestRepository === null) {
                        throw new LogicException('PushedAuthorizationRequestRepository is not configured.');
                    }
                    $parEntity = $this->pushedAuthorizationRequestRepository->findByRequestUri($requestUri);
                    if ($parEntity === null) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'Pushed authorization request not found or expired.',
                        );
                    }
                    if ($parEntity->isConsumed()) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'Pushed authorization request has already been consumed.',
                        );
                    }

                    $clientId = isset($params['client_id']) && is_string($params['client_id']) ?
                    $params['client_id'] :
                    null;
                    if ($clientId !== null && $clientId !== $parEntity->getClientId()) {
                        throw OidcServerException::invalidRequest(
                            'client_id',
                            'Client ID does not match the pushed authorization request client ID.',
                        );
                    }

                    $request = $request->withQueryParams($parEntity->getParameters())->withParsedBody([]);
                    $parRequestUri = $requestUri;
                } elseif (str_starts_with(strtolower($requestUri), 'https://')) {
                    if (
                        $this->requestParamsResolver === null ||
                        $this->jwksResolver === null ||
                        $this->requestObject === null ||
                        $this->moduleConfig === null
                    ) {
                        throw new LogicException(
                            'Required dependencies for JAR request_uri fetching are not configured.',
                        );
                    }

                    $clientId = isset($params['client_id']) && is_string($params['client_id']) ?
                    $params['client_id'] :
                    null;
                    if (empty($clientId)) {
                        throw OidcServerException::invalidRequest(
                            'client_id',
                            'Client ID is required when using request_uri.',
                        );
                    }



                    $client = $this->clientRepository->getClientEntity($clientId);
                    if ($client === null) {
                        throw OidcServerException::invalidRequest('client_id', 'Client not found.');
                    }

                    if (!$client instanceof \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'Client is not supported.',
                        );
                    }

                    $allowedRequestUris = $client->getRequestUris();
                    if (!in_array($requestUri, $allowedRequestUris, true)) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'The request_uri is not registered for this client.',
                        );
                    }

                    try {
                        $jwtString = $this->requestObject->requestUriFetcher()->fetch(
                            $requestUri,
                            $this->moduleConfig->getRequestUriTimeout(),
                            $this->moduleConfig->getRequestUriMaxSizeBytes(),
                        );
                    } catch (\Throwable $t) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'Failed to fetch request_uri: ' . $t->getMessage(),
                        );
                    }

                    try {
                        $requestObject = $this->requestObject->jarRequestObjectFactory()->fromToken($jwtString);
                        $jwks = $this->jwksResolver->forClient($client);
                        if ($jwks === null) {
                            throw new \Exception('Client JWKS not available.');
                        }
                        $requestObject->verifyWithKeySet($jwks);

                        if ($requestObject->getClientId() !== $client->getIdentifier()) {
                            throw new \Exception('client_id claim in request object does not match.');
                        }

                        $jwtPayload = $requestObject->getPayload();
                        $mergedParams = array_merge($params, $jwtPayload);
                        unset($mergedParams['request_uri']);
                        unset($mergedParams['request']);

                        $request = $request->withQueryParams($mergedParams)->withParsedBody([]);
                    } catch (\Throwable $t) {
                        throw OidcServerException::invalidRequest(
                            'request_uri',
                            'Invalid Request Object at request_uri: ' . $t->getMessage(),
                        );
                    }
                } else {
                    throw OidcServerException::invalidRequest(
                        'request_uri',
                        'Invalid request_uri scheme/format.',
                    );
                }
            }

            // Check if PAR is required
            $currentQueryParams = $request->getQueryParams();
            $currentBodyParams = $request->getParsedBody();
            $currentParams = array_merge(
                $currentQueryParams,
                is_array($currentBodyParams) ? $currentBodyParams : [],
            );
            $resolvedClientId = isset($currentParams['client_id']) && is_string($currentParams['client_id']) ?
            $currentParams['client_id'] :
            null;

            $parRequired = $this->moduleConfig?->getRequirePushedAuthorizationRequests() ?? false;

            if (is_string($resolvedClientId) && $resolvedClientId !== '') {
                $resolvedClient = $this->clientRepository->getClientEntity($resolvedClientId);
                if ($resolvedClient instanceof \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface) {
                    if ($resolvedClient->getRequirePushedAuthorizationRequests()) {
                        $parRequired = true;
                    }
                }
            }

            if ($parRequired && $parRequestUri === null) {
                throw OidcServerException::invalidRequest(
                    'request_uri',
                    'Pushed Authorization Request (PAR) is required.',
                );
            }

            $rulesToExecute = [
                StateRule::class,
                ClientRule::class,
                ClientRedirectUriRule::class,
                ResponseModeRule::class,
            ];

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
        /** @var ?string $state */
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        /** @var string $redirectUri */
        $redirectUri = $resultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        /** @var \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode */
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
                if ($authorizationRequest instanceof AuthorizationRequest && isset($parRequestUri)) {
                    $authorizationRequest->setParRequestUri($parRequestUri);
                }
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

        /** @var \SimpleSAML\OpenID\Core\IdToken|null $idTokenHint */
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
