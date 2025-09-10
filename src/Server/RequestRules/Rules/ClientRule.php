<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\FederationParticipationValidator;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use SimpleSAML\OpenID\Federation;
use Throwable;

/**
 * Resolve a client instance based on a client_id or request object.
 */
class ClientRule extends AbstractRule
{
    protected const KEY_REQUEST_OBJECT_JTI = 'request_object_jti';

    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        protected ClientRepository $clientRepository,
        protected ModuleConfig $moduleConfig,
        protected ClientEntityFactory $clientEntityFactory,
        protected Federation $federation,
        protected JwksResolver $jwksResolver,
        protected FederationParticipationValidator $federationParticipationValidator,
        protected ?FederationCache $federationCache = null,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }

    /**
     * @inheritDoc
     * @throws \JsonException
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\EntityStatementException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \SimpleSAML\OpenID\Exceptions\JwksException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \SimpleSAML\OpenID\Exceptions\RequestObjectException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustChainException
     * @throws \SimpleSAML\OpenID\Exceptions\TrustMarkException
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
                'Request object error: ' . $exception->getMessage(),
                $exception,
            );
        }

        // We have a Federation compatible Request Object.
        // The Audience (aud) value MUST be or include the OP's Issuer Identifier URL.
        (in_array($this->moduleConfig->getIssuer(), $requestObject->getAudience(), true)) ||
        throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'Invalid audience.');

        // Check for reuse of the Request Object. Request Object MUST only be used once (by OpenID Federation spec).
        if ($this->federationCache) {
            ($this->federationCache->has(self::KEY_REQUEST_OBJECT_JTI, $requestObject->getJwtId()) === false)
            || throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'Request Object reused.');
        }

        $clientEntityId = $requestObject->getIssuer();
        // Make sure that the Client ID is valid URL.
        (preg_match(ClientForm::REGEX_HTTP_URI_PATH, $requestObject->getIssuer())) ||
        throw OidcServerException::invalidRequest(ParamsEnum::Request->value, 'Client ID is not valid URI.');

        // We are ready to resolve trust chain.
        // TODO mivanci v7 Request Object can contain trust_chain claim, so also implement resolving using that claim.
        // Note that this is only possible if we have JWKS configured for common TA, so we can check TA Configuration
        // signature.
        try {
            $trustChain = $this->federation->trustChainResolver()->for(
                $clientEntityId,
                $this->moduleConfig->getFederationTrustAnchorIds(),
            )->getShortest();
        } catch (ConfigurationError $exception) {
            throw OidcServerException::serverError(
                'invalid OIDC configuration: ' . $exception->getMessage(),
                $exception,
            );
        } catch (Throwable $exception) {
            throw OidcServerException::invalidTrustChain(
                'error while trying to resolve trust chain: ' . $exception->getMessage(),
                null,
                $exception,
            );
        }

        // Validate TA with locally saved JWKS, if available.
        $trustAnchorEntityConfiguration = $trustChain->getResolvedTrustAnchor();
        $localTrustAnchorJwksJson = $this->moduleConfig
            ->getTrustAnchorJwksJson($trustAnchorEntityConfiguration->getIssuer());
        if (!is_null($localTrustAnchorJwksJson)) {
            /** @psalm-suppress MixedArgument */
            $localTrustAnchorJwks = $this->federation->helpers()->json()->decode($localTrustAnchorJwksJson);
            if (!is_array($localTrustAnchorJwks)) {
                throw OidcServerException::serverError('Unexpected JWKS format.');
            }
            $trustAnchorEntityConfiguration->verifyWithKeySet($localTrustAnchorJwks);
        }

        $clientFederationEntity = $trustChain->getResolvedLeaf();

        if ($clientFederationEntity->getIssuer() !== $clientEntityId) {
            throw OidcServerException::invalidTrustChain(
                'Client entity ID mismatch in request object and configuration statement.',
            );
        }
        try {
            $clientMetadata = $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty);
        } catch (Throwable $exception) {
            throw OidcServerException::invalidTrustChain(
                'Error while trying to resolve relying party metadata: ' . $exception->getMessage(),
                null,
                $exception,
            );
        }

        if (is_null($clientMetadata)) {
            throw OidcServerException::invalidTrustChain('No relying party metadata available.');
        }

        // We have client metadata resolved. Check if the client exists in storage, as it may be previously registered
        // but marked as expired.
        $existingClient = $this->clientRepository->findById($clientEntityId);

        if ($existingClient && ($existingClient->isEnabled() === false)) {
            throw OidcServerException::accessDenied('Client is disabled.');
        }

        if ($existingClient && ($existingClient->getRegistrationType() !== RegistrationTypeEnum::FederatedAutomatic)) {
            throw OidcServerException::accessDenied(
                'Unexpected existing client registration type: ' . $existingClient->getRegistrationType()->value,
            );
        }

        // Resolve client registration metadata
        $registrationClient = $this->clientEntityFactory->fromRegistrationData(
            $clientMetadata,
            RegistrationTypeEnum::FederatedAutomatic,
            $this->helpers->dateTime()->getFromTimestamp($trustChain->getResolvedExpirationTime()),
            $existingClient,
            $clientEntityId,
            $clientFederationEntity->getJwks()->getValue(),
            $request,
        );

        ($clientJwks = $this->jwksResolver->forClient($registrationClient)) ||
        throw OidcServerException::accessDenied('Client JWKS not available.');

        // Verify signature on Request Object using client JWKS.
        $requestObject->verifyWithKeySet($clientJwks);

        // Check if federation participation is limited by Trust Marks.
        if (
            $this->moduleConfig->isFederationParticipationLimitedByTrustMarksFor(
                $trustAnchorEntityConfiguration->getIssuer(),
            )
        ) {
            $this->federationParticipationValidator->byTrustMarksFor($trustChain);
        }

        // All is verified, We can persist (new) client registration.
        if ($existingClient) {
            $this->clientRepository->update($registrationClient);
        } else {
            $this->clientRepository->add($registrationClient);
        }

        // Mark Request Object as used.
        $this->federationCache?->set(
            $requestObject->getJwtId(),
            $this->helpers->dateTime()->getSecondsToExpirationTime($requestObject->getExpirationTime()),
            self::KEY_REQUEST_OBJECT_JTI,
            $requestObject->getJwtId(),
        );

        // We will also update result for RequestParameterRule (inject value from here), since the request object
        // is already resolved.
        $currentResultBag->add(new Result(RequestObjectRule::class, $requestObject->getPayload()));

        return new Result($this->getKey(), $registrationClient);
    }
}
