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
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class AuthorizationServer extends OAuth2AuthorizationServer
{
    /** @psalm-suppress PossiblyUnusedProperty Private property in parent. */
    protected ClientRepositoryInterface $clientRepository;

    protected RequestRulesManager $requestRulesManager;

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
    public function validateAuthorizationRequest(ServerRequestInterface $request): OAuth2AuthorizationRequest
    {
        $rulesToExecute = [
            StateRule::class,
            ClientRule::class,
            RedirectUriRule::class,
        ];

        try {
            $resultBag = $this->requestRulesManager->check(
                $request,
                $rulesToExecute,
                false,
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            );
        } catch (OidcServerException $exception) {
            $reason = sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        // state and redirectUri is used here, so we can return HTTP redirect error in case of invalid response_type.
        /** @var ?string $state */
        $state = $resultBag->getOrFail(StateRule::class)->getValue();
        /** @var string $redirectUri */
        $redirectUri = $resultBag->getOrFail(RedirectUriRule::class)->getValue();

        foreach ($this->enabledGrantTypes as $grantType) {
            if ($grantType->canRespondToAuthorizationRequest($request)) {
                if (! $grantType instanceof AuthorizationValidatableWithRequestRules) {
                    throw OidcServerException::serverError('grant type must be validatable with already validated ' .
                                                           'result bag');
                }

                return $grantType->validateAuthorizationRequestWithRequestRules($request, $resultBag);
            }
        }

        throw OidcServerException::unsupportedResponseType($redirectUri, $state);
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
                false,
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            );
        } catch (OidcServerException $exception) {
            $reason = sprintf("%s %s", $exception->getMessage(), $exception->getHint() ?? '');
            throw new BadRequest($reason);
        }

        /** @var \Lcobucci\JWT\UnencryptedToken|null $idTokenHint */
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
