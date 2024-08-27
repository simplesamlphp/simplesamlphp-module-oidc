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

class ResponseTypeRule extends AbstractRule
{
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
        $requestParams = $this->getAllRequestParamsBasedOnAllowedMethods(
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        ) ?? [];

        if (!isset($requestParams['response_type']) || !isset($requestParams['client_id'])) {
            throw  OidcServerException::invalidRequest('Missing response_type');
        }

        // TODO consider checking for supported response types, for example, from configuration...

        return new Result($this->getKey(), $requestParams['response_type']);
    }
}
