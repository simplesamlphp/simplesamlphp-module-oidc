<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class IssuerStateRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly IssuerStateRepository $issuerStateRepository,
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
        $loggerService->debug('IssuerStateRule: Running issuer state rule.');

        $issuerState = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::IssuerState->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($issuerState === null) {
            return null;
        }

        if ($this->issuerStateRepository->findValid($issuerState) === null) {
            $loggerService->error('IssuerStateRule: Invalid issuer state: ' . $issuerState);
            throw OidcServerException::invalidRequest(ParamsEnum::IssuerState->value);
        }

        $loggerService->debug('IssuerStateRule: Valid issuer state: ' . $issuerState);

        return new Result($this->getKey(), $issuerState);
    }
}
