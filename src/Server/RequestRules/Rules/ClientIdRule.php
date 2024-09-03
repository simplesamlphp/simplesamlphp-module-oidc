<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Federation;

class ClientIdRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        protected ClientRepositoryInterface $clientRepository,
        protected ModuleConfig $moduleConfig,
        protected Federation $federation,
    ) {
        parent::__construct($requestParamsResolver);
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
        /** @var ?string $clientId */
        $clientId = $this->requestParamsResolver->getBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? $request->getServerParams()['PHP_AUTH_USER'] ?? null;

        if ($clientId === null) {
            throw OidcServerException::invalidRequest('client_id');
        }

        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client instanceof ClientEntityInterface) {
            return new Result($this->getKey(), $client);
        }

        // If federation capabilities are not enabled, we don't have anything else to do.
        if ($this->moduleConfig->getFederationEnabled() === false) {
            throw OidcServerException::invalidClient($request);
        }

        // Federation is enabled.
        // Check if we have a request object available. If not, we don't have anything else to do.
        $requestParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Request->value,
            $request,
            $allowedServerRequestMethods,
        );

        if (is_null($requestParam)) {
            throw OidcServerException::invalidClient($request);
        }

        // We have a request object available. We must verify that it is the one compatible with OpenID Federation
        // specification (not only Core specification).
        // TDOO mivanci continue. See how to operate this together with RequestParameterRule (maybe inject it from here)
//        $requestObject = $this->requestParamsResolver->parseFederationRequestObjectToken($requestParam);

        return new Result($this->getKey(), $client);
    }
}
