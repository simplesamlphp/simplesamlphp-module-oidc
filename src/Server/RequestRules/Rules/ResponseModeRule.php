<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

class ResponseModeRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        private readonly QueryResponseMode $queryResponseMode,
        private readonly FragmentResponseMode $fragmentResponseMode,
        private readonly FormPostResponseMode $formPostResponseMode,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


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
    ): ?ResultInterface {
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        // response_mode requires client_id to be present
        if (
            !isset($requestParams[ParamsEnum::ClientId->value])
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ClientId->value,
                'Missing client_id',
            );
        }

        $responseModeValue = isset($requestParams[ParamsEnum::ResponseMode->value]) ?
        (string)$requestParams[ParamsEnum::ResponseMode->value] : null;
        $loggerService->debug('ResponseModeRule: response_mode requestParams value: ' . ($responseModeValue ?? 'null'));


        // if response_mode is not set, we set the default
        //  to 'code' if not set. Error will be thrown by ResponseTypeRule.
        $responseType = isset($requestParams[ParamsEnum::ResponseType->value]) ?
        (string)$requestParams[ParamsEnum::ResponseType->value] : 'code';
        if (!$responseModeValue) {
            $responseModeValue = str_contains($responseType, 'token') ?
            ResponseModesEnum::Fragment->value : ResponseModesEnum::Query->value;
        }

        // Verify if response_mode is one of 'query', 'fragment', 'form_post'
        if (
            !in_array(
                $responseModeValue,
                [
                    ResponseModesEnum::Query->value,
                    ResponseModesEnum::Fragment->value,
                    ResponseModesEnum::FormPost->value,
                ],
                true,
            )
        ) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::ResponseMode->value,
                'Invalid response_mode',
            );
        }

        // Validate whether response_mode is allowed by client configuration
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue();
        $currentResultBag->getOrFail(StateRule::class)->getValue();

        $allowedResponseModes = $client->getAllowedResponseModes();
        if (!in_array($responseModeValue, $allowedResponseModes, true)) {
            throw OidcServerException::invalidRequest(
                'response_mode',
                'response_mode "' . $responseModeValue . '" is not allowed for this client',
            );
        }

        // Resolve ResponseModeStrategy
        $responseMode = match ($responseModeValue) {
            ResponseModesEnum::Query->value => $this->queryResponseMode,
            ResponseModesEnum::Fragment->value => $this->fragmentResponseMode,
            ResponseModesEnum::FormPost->value => $this->formPostResponseMode,
            default => throw OidcServerException::invalidRequest(
                ParamsEnum::ResponseMode->value,
                'Unsupported response_mode. How did we get here?',
            ),
        };

        return new Result($this->getKey(), $responseMode);
    }
}
