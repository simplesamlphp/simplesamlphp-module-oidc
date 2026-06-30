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
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends AbstractRule<string>
 */
class RequiredNonceRule extends AbstractRule
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
        $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $state = $currentResultBag->getOrFail(StateRule::class)->getValue();

        $nonce = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::Nonce->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($nonce === null || $nonce === '') {
            $loggerService->notice('Authorization request rejected: required `nonce` parameter is missing.');
            throw OidcServerException::invalidRequest(
                ParamsEnum::Nonce->value,
                'nonce is required',
                null,
                $redirectUri,
                $state,
                $responseMode,
            );
        }

        return new Result($this->getKey(), $nonce);
    }
}
