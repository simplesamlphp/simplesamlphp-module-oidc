<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\EntityTypeEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Federation;
use Throwable;

class ClientIdRule extends AbstractRule
{
    protected const KEY_REQUEST_OBJECT_JTI = 'request_object_jti';

    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        protected ClientRepositoryInterface $clientRepository,
        protected ModuleConfig $moduleConfig,
        protected Federation $federation,
        protected ?FederationCache $federationCache = null,
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
        try {
            $requestObject = $this->requestParamsResolver->parseFederationRequestObjectToken($requestParam);
        } catch (Throwable $exception) {
            throw OidcServerException::invalidRequest(
                ParamsEnum::Request->value,
                'request object parse error',
                $exception,
            );
        }

        // We have a Federation compatible Request Object.
        // The Audience (aud) value MUST be or include the OP's Issuer Identifier URL.
        (in_array($this->moduleConfig->getIssuer(), $requestObject->getAudience(), true)) ||
        throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'invalid audience');

        // Check for reuse of the Request Object. Request Object MUST only be used once.
        (boolval(
            $this->federationCache?->has(self::KEY_REQUEST_OBJECT_JTI, $requestObject->getJwtId()),
        ) === false) || throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'request object reused');

        $clientEntityId =  $requestObject->getIssuer();
        // Make sure that the Client ID is valid URL.
        (preg_match(ClientForm::REGEX_HTTP_URI_PATH, $requestObject->getIssuer())) ||
        throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'client ID is not valid URI');

        // We are ready to resolve trust chain.
        // TODO mivanci Request Object can contain trust_chain claim. Implement resolving it using that claim. Note
        // that this is only possible if we have JWKS configured for common TA, so we can check TA Configuration
        // signature.
        try {
            $trustChain = $this->federation->trustChainResolver()->for(
                $clientEntityId,
                $this->moduleConfig->getFederationTrustAnchorIds(),
            );
        } catch (ConfigurationError $exception) {
            throw OidcServerException::serverError('invalid OIDC configuration', $exception);
        } catch (Throwable $exception) {
            throw OidcServerException::invalidTrustChain(
                'error while trying to resolve trust chain',
                null,
                $exception,
            );
        }

        try {
            $clientMetadata = $trustChain->getResolvedMetadata(EntityTypeEnum::OpenIdRelyingParty);
        } catch (Throwable $exception) {
            throw OidcServerException::invalidTrustChain(
                'error while trying to resolve relying party metadata',
                null,
                $exception,
            );
        }

        if (is_null($clientMetadata)) {
            throw OidcServerException::invalidTrustChain('no relying party metadata available');
        }

        // TODO mivanci continue We have client metadata. We now must try and create client entity and persist it.
        // To persist it, we must introduce new properties:
        //  * registration type (manual, federationAutomatic...)
        //  * expires_at (null if it does not expire or timestamp in the future).
        // TODO New properties must be taken into account while checking if client is valid
        // (check method ClientRepository::getClientEntity)
        // TODO Update result for RequestParameterRule (inject value from here)

        return new Result($this->getKey(), $client);
    }
}
