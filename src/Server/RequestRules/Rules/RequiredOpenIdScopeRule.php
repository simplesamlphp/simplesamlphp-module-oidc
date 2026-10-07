<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use Throwable;

/**
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<bool>
 */
class RequiredOpenIdScopeRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('RequiredOpenIdScopeRule::checkRule.');

        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        $validScopes = $currentResultBag->getOrFail(ScopeRule::class)->getValue();

        $isOpenIdScopePresent = (bool) array_filter(
            $validScopes,
            fn($scopeEntity) => $scopeEntity->getIdentifier() === 'openid',
        );

        $loggerService->debug(
            'RequiredOpenIdScopeRule: Is openid scope present: ',
            ['isOpenIdScopePresent' => $isOpenIdScopePresent],
        );

        try {
            if (! $isOpenIdScopePresent) {
                throw OidcServerException::invalidRequest(
                    'scope',
                    'Scope openid is required',
                    null,
                    $redirectUri,
                    $state,
                    $responseMode,
                );
            }
        } catch (Throwable $e) {
            if ($this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods)) {
                $loggerService->info('RequiredOpenIdScopeRule: Skippping openid scope check for VCI request.');
            } elseif ($this->isAllowedPlainOAuth2AuthorizationCodeRequest($request, $allowedServerRequestMethods)) {
                $loggerService->debug(
                    'RequiredOpenIdScopeRule: Skipping openid scope check for plain OAuth2 code request.',
                );
            } else {
                $loggerService->error('RequiredOpenIdScopeRule: Scope openid is required.');
                throw $e;
            }
        }

        return new Result($this->getKey(), true);
    }


    /**
     * An authorization code request without the openid scope is a plain OAuth 2.0 one (RFC 6749 section 4.1),
     * which is let through where the deployment enables it
     * (ModuleConfig::OPTION_PLAIN_OAUTH2_AUTHORIZATION_CODE_ENABLED). Only for the `code` response type: the
     * implicit grant's response types deliver an ID token, which only an OpenID Connect request can ask for.
     *
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function isAllowedPlainOAuth2AuthorizationCodeRequest(
        ServerRequestInterface $request,
        array $allowedServerRequestMethods,
    ): bool {
        if (!$this->moduleConfig->isPlainOAuth2AuthorizationCodeEnabled()) {
            return false;
        }

        $responseType = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::ResponseType->value,
            $request,
            $allowedServerRequestMethods,
        );

        return $responseType === ResponseTypesEnum::Code->value;
    }
}
