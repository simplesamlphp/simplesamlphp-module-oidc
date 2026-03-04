<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class RequiredOpenIdScopeRule extends AbstractRule
{
    /**
     * @inheritDoc
     * @throws \Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $loggerService->debug('RequiredOpenIdScopeRule::checkRule.');

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        /** @var string|null $state */
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
        /** @var \League\OAuth2\Server\Entities\ScopeEntityInterface[] $validScopes */
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
                    $useFragmentInHttpErrorResponses,
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
