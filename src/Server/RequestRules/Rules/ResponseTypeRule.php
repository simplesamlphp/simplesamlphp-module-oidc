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
class ResponseTypeRule extends AbstractRule
{
    /**
     * @inheritDoc
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
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        if (
            !isset($requestParams[ParamsEnum::ResponseType->value]) ||
            !isset($requestParams[ParamsEnum::ClientId->value])
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ResponseType->value,
                'Missing response_type or client_id',
            );
        }

        // No need to validate the value against a list of supported response types here: this rule only runs from
        // within a grant's request validation, which is reached only after AuthorizationServer has matched the
        // request to a grant via canRespondToAuthorizationRequest(). By grant selection therefore
        // already rejects unsupported response types (unsupportedResponseType) before this point.
        // TODO: Also, we currently don't store allowed response types per client, so nothing to validate in that
        // sense either. This should be fixed in the future, for example in DCR implementation.

        $responseType = (string)$requestParams[ParamsEnum::ResponseType->value];

        return new Result($this->getKey(), $responseType);
    }
}
