<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @extends AbstractRule<bool>
 */
class RequiredOpenIdScopeRule extends AbstractRule
{
    /**
     * @inheritDoc
     *
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
        } catch (\Throwable $e) {
            if ($this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods)) {
                $loggerService->info('RequiredOpenIdScopeRule: Skippping openid scope check for VCI request.');
            } else {
                $loggerService->error('RequiredOpenIdScopeRule: Scope openid is required.');
                throw $e;
            }
        }

        return new Result($this->getKey(), true);
    }
}
