<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

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
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {

        $loggerService->debug('ClientAuthenticationRule::checkRule');

        // TODO mivanci Instead of ClientRule which mandates client, this should
        // be refactored to use optional client_id parameter and then
        // fetch client if present.
        /** @var ?\SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $preFetchedClient */
        $preFetchedClient = $currentResultBag->get(ClientRule::class)?->getValue();

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
