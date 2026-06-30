<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
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
            $loggerService->notice(
                'Authorization request rejected: missing `response_type` or `client_id` parameter.',
            );
            throw OidcServerException::invalidRequest(
                ParamsEnum::ResponseType->value,
                'Missing response_type or client_id',
            );
        }

        // No need to validate the value against the globally supported response types here: this rule only runs
        // from within a grant's request validation, which is reached only after AuthorizationServer has matched
        // the request to a grant via canRespondToAuthorizationRequest(), so grant selection already rejects
        // globally unsupported response types before this point.

        $responseType = (string)$requestParams[ParamsEnum::ResponseType->value];

        // Per-client enforcement: if the client has explicitly registered a non-empty response_types list, the
        // requested response_type must be one of them. We enforce only when the value was explicitly registered
        // (present and non-empty in the client's metadata); clients that do not have it configured - or have it as
        // an empty list - are not constrained, preserving behavior for manually-managed and pre-DCR clients.
        // Dynamically registered clients always have it (the OIDC DCR default is applied at registration).
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        // getResponseTypes() returns the raw registered value (empty array when nothing is registered - it does not
        // synthesize the OIDC DCR spec default), so an empty list means "not configured" and is not enforced.
        $registeredResponseTypes = ($client instanceof ClientEntityInterface) ? $client->getResponseTypes() : [];

        if (
            $registeredResponseTypes !== [] &&
            !in_array($responseType, $registeredResponseTypes, true)
        ) {
            $loggerService->error(
                'ResponseTypeRule: response_type not registered for client.',
                ['response_type' => $responseType, 'registered' => $registeredResponseTypes],
            );
            $redirectUri = $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
            $state = $currentResultBag->getOrFail(StateRule::class)->getValue();
            throw OidcServerException::unsupportedResponseType($redirectUri, $state, $responseMode);
        }

        return new Result($this->getKey(), $responseType);
    }
}
