<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends AbstractRule<\SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod>
 */
class ClientAuthenticationRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
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

        $loggerService->debug('ClientAuthenticationRule::checkRule');

        // Use a client that an upstream rule may have already resolved (e.g. ClientRule). If none is available,
        // optionally pre-fetch it using the client_id request parameter. The client_id parameter is intentionally
        // NOT mandatory here: some client authentication methods convey the client identity by other means (e.g.
        // private_key_jwt via the assertion issuer, client_secret_basic via the Authorization header). When no client
        // is pre-fetched, the resolver derives and authenticates the client purely from the presented authentication
        // material, and cross-checks any client_id it does find against that material.
        $preFetchedClient = $currentResultBag->get(ClientRule::class)?->getValue();

        if (!$preFetchedClient instanceof ClientEntityInterface) {
            $clientId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
                ParamsEnum::ClientId->value,
                $request,
                $allowedServerRequestMethods,
            );

            $preFetchedClient = is_string($clientId) ?
            $this->authenticatedOAuth2ClientResolver->findActiveClient($clientId) :
            null;
        }

        $resolvedClientAuthenticationMethod = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod(
            request: $request,
            preFetchedClient: $preFetchedClient,
        );

        if (is_null($resolvedClientAuthenticationMethod)) {
            throw OidcServerException::accessDenied('Not a single client authentication method presented.');
        }

        // Ensure we that the method is not 'None' if client is confidential.
        if (
            $resolvedClientAuthenticationMethod->getClientAuthenticationMethod()->isNone() &&
            $resolvedClientAuthenticationMethod->getClient()->isConfidential()
        ) {
            throw OidcServerException::accessDenied(
                'Confidential client must use an authentication method other than "none".',
            );
        }

        return new Result($this->getKey(), $resolvedClientAuthenticationMethod);
    }
}
