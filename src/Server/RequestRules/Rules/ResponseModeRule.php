<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Helpers;

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
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        $requestParams = $this->requestParamsResolver->getAllBasedOnAllowedMethods(
            $request,
            $allowedServerRequestMethods,
        );

        // response_mode requires client_id and response_type to be present
        if (
            !isset($requestParams[ParamsEnum::ClientId->value]) ||
            !isset($requestParams[ParamsEnum::ResponseType->value])) {
            throw  OidcServerException::invalidRequest('Missing client_id or response_type');
        }

        $reponseModeValue = $requestParams[ParamsEnum::ResponseMode->value] ?? null;
        $loggerService->debug('ResponseModeRule: resolved response_mode value: ' . ($reponseModeValue ?? 'null'));


        // if response_mode is not set, we set the default
        $responseType = $requestParams[ParamsEnum::ResponseType->value];
        if (!$reponseModeValue) {
            switch ($responseType) {
                case str_contains($responseType, 'token'):
                case str_contains($responseType, 'id_token'):
                    $reponseModeValue = 'fragment';
                    break;
                default:
                    // for other response types, the default is query
                    $reponseModeValue = 'query';
            }
        }

        // Verify if response_mode is one of 'query', 'fragment', 'form_post'
        if (!in_array(
            $reponseModeValue,
            ['query', 'fragment', 'form_post'],
            true,
        )) {
            throw OidcServerException::invalidRequest('Invalid response_mode');
        }

        // TODO: validate whether response_mode is allowed by configuration

        // Resolve ResponseModeStrategy
        switch ($reponseModeValue) {
            case 'query':
                $responseMode = $this->queryResponseMode;
                break;
            case 'fragment':
                $responseMode = $this->fragmentResponseMode;
                break;
            case 'form_post':
                $responseMode = $this->formPostResponseMode;
                break;
            default:
                throw OidcServerException::invalidRequest('Unsupported response_mode. How did we get here?');
        }

        return new Result($this->getKey(), $responseMode);
    }
}
