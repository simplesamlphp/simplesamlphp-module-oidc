<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server;

use League\OAuth2\Server\AuthorizationServer as OAuth2AuthorizationServer;
use SimpleSAML\Error\BadRequest;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest as OAuth2AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Server\Grants\Interfaces\AuthorizationValidatableWithClientAndRedirectUriInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\RedirectUriRule;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules\StateRule;

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
        $client = $resultBag->getOrFail(ClientIdRule::class)->getValue();
        $redirectUri = $resultBag->getOrFail(RedirectUriRule::class)->getValue();

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                if (! $grantType instanceof AuthorizationValidatableWithClientAndRedirectUriInterface) {
                    throw OidcServerException::serverError('Grant type must be validatable with already validated ' .
                                                           'client and redirect_uri');
                }

                return $grantType->validateAuthorizationRequestWithClientAndRedirectUri(
                    $request,
                    $client,
                    $redirectUri,
                    $state
                );
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
    }
}
