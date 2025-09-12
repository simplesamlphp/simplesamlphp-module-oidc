<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class RedirectUriRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ModuleConfig $moduleConfig,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

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
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();
        if (! $client instanceof ClientEntityInterface) {
            throw new LogicException('Can not check redirect_uri, client is not ClientEntityInterface.');
        }

        $redirectUri = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::RedirectUri->value,
            $request,
            $allowedServerRequestMethods,
        );

        // On OAuth2 redirect_uri is optional if there is only one registered, however we will always require it
        // since this is OIDC oriented package and in OIDC this parameter is required.
        if ($redirectUri === null) {
            throw OidcServerException::invalidRequest(ParamsEnum::RedirectUri->value);
        }

        $clientRedirectUri = $client->getRedirectUri();

        try {
            if (is_string($clientRedirectUri) && (strcmp($clientRedirectUri, $redirectUri) !== 0)) {
                throw OidcServerException::invalidClient($request);
            } elseif (
                is_array($clientRedirectUri) &&
                in_array($redirectUri, $clientRedirectUri, true) === false
            ) {
                throw OidcServerException::invalidRequest(ParamsEnum::RedirectUri->value);
            }
        } catch (\Throwable $exception) {
            if (
                $this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods) &&
                $this->moduleConfig->getVerifiableCredentialEnabled() &&
                $this->moduleConfig->getAllowNonRegisteredClientsForVci()
            ) {
                $loggerService->debug(
                    'RedirectUriRule: Verifiable Credential capabilities with non-registered clients are enabled. ' .
                    'Checking for allowed redirect URI prefixes.',
                );

                /** @psalm-suppress MixedAssignment */
                foreach (
                    $this->moduleConfig->getAllowedRedirectUriPrefixesForNonRegisteredClientsForVci(
                    ) as $clientRedirectUriPrefix
                ) {
                    if (str_starts_with($redirectUri, (string)$clientRedirectUriPrefix)) {
                        $loggerService->debug(
                            'RedirectUriRule: Redirect URI param starts with allowed redirect URI prefix, continuing.',
                            ['redirect_uri' => $redirectUri, 'redirect_uri_prefix' => $clientRedirectUriPrefix],
                        );

                        return new Result($this->getKey(), $redirectUri);
                    }
                }

                $loggerService->error(
                    'RedirectUriRule: Redirect URI param does not start with allowed redirect URI prefix, stopping.',
                    ['redirect_uri' => $redirectUri],
                );

                throw $exception;
            } else {
                $loggerService->debug(
                    'RedirectUriRule: Verifiable Credential capabilities with non-registered clients are not enabled. ',
                );
                $loggerService->error(
                    'RedirectUriRule: Redirect URI param does not correspond to the client redirect URI.',
                    ['redirect_uri' => $redirectUri, 'client_redirect_uri' => $clientRedirectUri],
                );
                throw $exception;
            }
        }

        $loggerService->debug(
            'RedirectUriRule: Redirect URI param corresponds to the client redirect URI.',
            ['redirect_uri' => $redirectUri, 'client_redirect_uri' => $clientRedirectUri],
        );

        return new Result($this->getKey(), $redirectUri);
    }
}
