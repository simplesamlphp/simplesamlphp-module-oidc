<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\PreAuthorizedCodeClient;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * Work out which client a token request redeeming a pre-authorized code comes from, authenticating it when it
 * presents credentials.
 *
 * For the pre-authorized code grant OpenID4VCI 1.0 (section 6.1) makes client authentication OPTIONAL and wants
 * `client_id` only where the authentication method relies on it, while keeping RFC 6749 section 3.2.1 in force.
 * A wallet can therefore turn up in one of four ways, and the result says which client the access token is
 * issued to or bound to, which is also what the key proof's `iss` claim is later checked against at the
 * credential endpoint:
 *
 * - With credentials (a client assertion, a Basic Authorization header or a client secret): the client they
 *   name has to be registered and the credentials have to verify, or the request is refused with
 *   `invalid_client` (RFC 7521 section 4.2.1). Credentials which cannot be checked are a refusal, not a case
 *   of anonymous access, and a `client_id` sent alongside has to name the same client (RFC 7521 section 4.2).
 *   The result is that registered client.
 * - With a `client_id` naming a registered client and no credentials: accepted as that client only where its
 *   registration allows it, so a confidential client is refused (RFC 6749 section 3.2.1), as is a public
 *   client registered with another `token_endpoint_auth_method`. The result is that registered client.
 * - With a `client_id` naming no registered client: the self-declared identifier of a non-registered wallet.
 *   Nothing can authenticate it, and nothing depends on it beyond that `iss` check. The result carries the
 *   identifier alone.
 * - With neither: anonymous access, and no result.
 *
 * A registered client is not checked against its registered `grant_types`: the pre-authorized code grant is an
 * OP capability rather than a per-client registrable grant type (see OpMetadataService), so no registration
 * could name it.
 *
 * ClientAuthenticationRule is not reused here because it takes the absence of any method for a refusal, which
 * for this grant it is not.
 *
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<\SimpleSAML\Module\oidc\ValueAbstracts\PreAuthorizedCodeClient>
 */
class PreAuthorizedCodeClientRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected readonly AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver,
        protected readonly ClientRepository $clientRepository,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @inheritDoc
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('PreAuthorizedCodeClientRule::checkRule');

        $clientId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            $allowedServerRequestMethods,
        );
        if ($clientId === '') {
            $clientId = null;
        }

        $presentsCredentials = $this->authenticatedOAuth2ClientResolver->presentsClientCredentials($request);
        $registeredClient = $clientId === null ? null : $this->clientRepository->findById($clientId);

        if ($presentsCredentials || $registeredClient !== null) {
            // Only an active client is handed over as pre-fetched: the resolver takes a pre-fetched client on
            // trust, and its own lookup is what refuses a disabled or expired one.
            $preFetchedClient = $registeredClient !== null && $registeredClient->isEnabled() &&
            !$registeredClient->isExpired() ? $registeredClient : null;

            $resolved = $this->authenticatedOAuth2ClientResolver->forAnySupportedMethod($request, $preFetchedClient);

            if ($resolved === null) {
                $loggerService->warning(
                    'Token request rejected: the client could not be authenticated.',
                    ['client_id' => $clientId, 'presents_credentials' => $presentsCredentials],
                );
                throw OidcServerException::invalidClient($request);
            }

            $resolvedClientId = $resolved->getClient()->getIdentifier();

            if ($clientId !== null && $clientId !== $resolvedClientId) {
                $loggerService->warning(
                    'Token request rejected: `client_id` does not name the client the credentials authenticate.',
                    ['client_id' => $clientId, 'authenticated_client_id' => $resolvedClientId],
                );
                throw OidcServerException::invalidClient($request);
            }

            $loggerService->debug(
                'PreAuthorizedCodeClientRule: client resolved.',
                [
                    'client_id' => $resolvedClientId,
                    'method' => $resolved->getClientAuthenticationMethod()->value,
                ],
            );

            return new Result($this->getKey(), PreAuthorizedCodeClient::registered($resolved->getClient()));
        }

        if ($clientId !== null) {
            $loggerService->debug(
                'PreAuthorizedCodeClientRule: non-registered client identified by `client_id` alone.',
                ['client_id' => $clientId],
            );

            return new Result($this->getKey(), PreAuthorizedCodeClient::selfDeclared($clientId));
        }

        $loggerService->debug('PreAuthorizedCodeClientRule: anonymous access, no client identified.');

        return null;
    }
}
