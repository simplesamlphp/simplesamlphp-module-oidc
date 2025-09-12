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
use SimpleSAML\OpenID\Exceptions\JwsException;
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
        protected LoggerService $loggerService,
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

        $this->loggerService->debug(
            'ClientRule: Request parameters:',
            $this->requestParamsResolver->getAllBasedOnAllowedMethods(
                $request,
                $allowedServerRequestMethods,
            ),
        );

        /** @var ?string $clientId */
        $clientId = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::ClientId->value,
            $request,
            $allowedServerRequestMethods,
        ) ?? $request->getServerParams()['PHP_AUTH_USER'] ?? null;

        if ($clientId === null) {
            $this->loggerService->debug(
                'ClientRule: Client ID not found in request parameters or PHP_AUTH_USER.',
            );
            // Check to see if this is a Verifiable Credential Request. Is yes, check if VCI is
            // enabled, and if client_id is allowed to be empty. We know that this is a VCI request because the
            // Issuer State parameter must be present.
            if (
                $this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods) &&
                $this->moduleConfig->getVerifiableCredentialEnabled() &&
                $this->moduleConfig->getAllowVciAuthorizationCodeRequestsWithoutClientId() &&
                $this->moduleConfig->getAllowNonRegisteredClientsForVci()
            ) {
                // We will use a VCI generic client in this case.
                $this->loggerService->warning(
                    'ClientRule: VCI authorization code request without client_id detected.' .
                    ' Using generic VCI client.',
                );

                return new Result($this->getKey(), $this->getGenericVciClient());
            }

            throw OidcServerException::invalidRequest('client_id');
        }

        $this->loggerService->debug(
            'ClientRule: Client ID: ' . $clientId,
        );

        $client = $this->clientRepository->getClientEntity($clientId);

        if ($client instanceof ClientEntityInterface) {
            $this->loggerService->debug(
                'ClientRule: Client found in storage: ' . $client->getIdentifier(),
            );
            return new Result($this->getKey(), $client);
        }

        // If federation capabilities are not enabled, we don't have anything else to do.
        if ($this->moduleConfig->getFederationEnabled()) {
            $this->loggerService->debug(
                'ClientRule: Federation capabilities are enabled.',
            );

            $client = $this->resolveFromFederation($request, $allowedServerRequestMethods, $currentResultBag);

            if ($client instanceof ClientEntityInterface) {
                $this->loggerService->debug(
                    'ClientRule: Client resolved from federation: ' . $client->getIdentifier(),
                );
                return new Result($this->getKey(), $client);
            }
        } else {
            $this->loggerService->debug(
                'ClientRule: Federation capabilities are not enabled.',
            );
        }

        if (
            $this->requestParamsResolver->isVciAuthorizationCodeRequest($request, $allowedServerRequestMethods) &&
            $this->moduleConfig->getVerifiableCredentialEnabled() &&
            $this->moduleConfig->getAllowNonRegisteredClientsForVci()
        ) {
            $this->loggerService->debug(
                'ClientRule: Verifiable Credential capabilities with non-registered clients are enabled. ' .
                'Falling back to generic VCI client.',
            );

            return new Result($this->getKey(), $this->getGenericVciClient());
        } else {
            $this->loggerService->debug(
                'ClientRule: Verifiable Credential capabilities with non-registered clients are not enabled.',
            );
        }

        $this->loggerService->debug('ClientRule: Client could not be resolved.');

        throw OidcServerException::invalidClient($request);
    }

    /**
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedMethods
     */
    public function resolveFromFederation(
        ServerRequestInterface $request,
        array $allowedMethods,
        ResultBagInterface $currentResultBag,
    ): ?ClientEntityInterface {
        $this->loggerService->debug('ClientRule: Resolving client from federation.');
        // Federation is enabled.
        // Check if we have a request object available. If not, we don't have anything else to do.
        $requestParam = $this->requestParamsResolver->getFromRequestBasedOnAllowedMethods(
            ParamsEnum::Request->value,
            $request,
            $allowedMethods,
        );

        if (is_null($requestParam)) {
            $this->loggerService->error('ClientRule: No request param available, nothing to do.');
            return null;
        }

        $this->loggerService->debug('ClientRule: Request param available.', ['requestParam' => $requestParam]);

        // We have a request object available. We must verify that it is the one compatible with OpenID Federation
        // specification (not only Core specification).
        try {
            $requestObject = $this->requestParamsResolver->parseFederationRequestObjectToken($requestParam);
        } catch (Throwable $exception) {
            $this->loggerService->error('ClientRule: Request object error: ' . $exception->getMessage());
            return null;
        }

        $this->loggerService->debug('ClientRule: Request object parsed successfully.');

        // We have a Federation-compatible Request Object.
        // The Audience (aud) value MUST be or include the OP's Issuer Identifier URL.
        if (! in_array($this->moduleConfig->getIssuer(), $requestObject->getAudience(), true)) {
            $this->loggerService->error(
                'ClientRule: Request object audience mismatch.',
                ['expected' => $this->moduleConfig->getIssuer(), 'actual' => $requestObject->getAudience()],
            );
            return null;
        }

        // Check for reuse of the Request Object. Request Object MUST only be used once (by OpenID Federation spec).
        if (
            $this->federationCache &&
            $this->federationCache->has(self::KEY_REQUEST_OBJECT_JTI, $requestObject->getJwtId())
        ) {
            $this->loggerService->error(
                'ClientRule: Request object reused.',
                ['request_object_jti' => $requestObject->getJwtId()],
            );
            return null;
        }

        $clientEntityId = $requestObject->getIssuer();
        // Make sure that the Client Entity ID is valid URL.
        if (!preg_match(ClientForm::REGEX_HTTP_URI_PATH, $clientEntityId)) {
            $this->loggerService->error(
                'ClientRule: Client Entity ID is not valid URI.',
                ['client_id' => $clientEntityId],
            );
            return null;
        }

        $this->loggerService->debug('ClientRule: Client Entity ID is valid URI.');

        // We are ready to resolve trust chain.
        // TODO mivanci v7 Request Object can contain trust_chain claim, so also implement resolving using that claim.
        // Note that this is only possible if we have JWKS configured for common TA, so we can check TA Configuration
        // signature.
        try {
            $this->loggerService->debug('ClientRule: Resolving trust chain.');
            $trustChain = $this->federation->trustChainResolver()->for(
                $clientEntityId,
                $this->moduleConfig->getFederationTrustAnchorIds(),
            )->getShortest();
        } catch (ConfigurationError $exception) {
            $this->loggerService->error('ClientRule: Invalid OIDC configuration: ' . $exception->getMessage());
            return null;
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'ClientRule: Error while trying to resolve trust chain: ' . $exception->getMessage(),
            );
            return null;
        }

        // Validate TA with locally saved JWKS, if available.
        $trustAnchorEntityConfiguration = $trustChain->getResolvedTrustAnchor();
        $localTrustAnchorJwksJson = $this->moduleConfig
            ->getTrustAnchorJwksJson($trustAnchorEntityConfiguration->getIssuer());
        if (!is_null($localTrustAnchorJwksJson)) {
            $this->loggerService->debug('ClientRule: Validating TA with locally saved JWKS.');
            /** @psalm-suppress MixedArgument */
            $localTrustAnchorJwks = $this->federation->helpers()->json()->decode($localTrustAnchorJwksJson);
            if (!is_array($localTrustAnchorJwks)) {
                $this->loggerService->error(
                    'ClientRule: Unexpected JWKS format for locally saved Trust Anchor JWKS.',
                );
                return null;
            }
            $trustAnchorEntityConfiguration->verifyWithKeySet($localTrustAnchorJwks);
            $this->loggerService->debug('ClientRule: TA with locally saved JWKS validated successfully.');
        }

        $clientFederationEntity = $trustChain->getResolvedLeaf();

        if ($clientFederationEntity->getIssuer() !== $clientEntityId) {
            $this->loggerService->error(
                'Client entity ID mismatch in request object and configuration statement.',
                ['expected' => $clientFederationEntity->getIssuer(), 'actual' => $clientEntityId],
            );
        }

        try {
            $this->loggerService->debug('ClientRule: Resolving relying party metadata.');
            $clientMetadata = $trustChain->getResolvedMetadata(EntityTypesEnum::OpenIdRelyingParty);
        } catch (Throwable $exception) {
            $this->loggerService->error(
                'ClientRule: Error while trying to resolve relying party metadata: ' . $exception->getMessage(),
            );
            return null;
        }

        if (is_null($clientMetadata)) {
            $this->loggerService->error('ClientRule: No relying party metadata available.');
            return null;
        }

        // We have client metadata resolved. Check if the client exists in storage, as it may be previously registered
        // but marked as expired.
        $existingClient = $this->clientRepository->findById($clientEntityId);

        if ($existingClient && ($existingClient->isEnabled() === false)) {
            $this->loggerService->error('ClientRule: Client is disabled:');
            return null;
        }

        if ($existingClient && ($existingClient->getRegistrationType() !== RegistrationTypeEnum::FederatedAutomatic)) {
            $this->loggerService->error(
                'Unexpected existing client registration type: ' . $existingClient->getRegistrationType()->value,
            );
            return null;
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

        $clientJwks = $this->jwksResolver->forClient($registrationClient);
        if (!is_array($clientJwks)) {
            $this->loggerService->debug('ClientRule: Client JWKS not available.');
            return null;
        }

        // Verify signature on Request Object using client JWKS.
        try {
            $requestObject->verifyWithKeySet($clientJwks);
        } catch (JwsException $e) {
            $this->loggerService->error(
                'ClientRule: Request object signature verification failed: ' . $e->getMessage(),
            );
            return null;
        }

        // Check if federation participation is limited by Trust Marks.
        if (
            $this->moduleConfig->isFederationParticipationLimitedByTrustMarksFor(
                $trustAnchorEntityConfiguration->getIssuer(),
            )
        ) {
            $this->loggerService->debug('ClientRule: Verifying trust marks for federation participation.');
            try {
                $this->federationParticipationValidator->byTrustMarksFor($trustChain);
            } catch (Throwable $e) {
                $this->loggerService->error(
                    'ClientRule: Trust marks for federation participation verification failed: ' . $e->getMessage(),
                );
                return null;
            }
        }

        $this->loggerService->debug('ClientRule: All verified, persisting client registration.');

        // All is verified, We can persist (new) client registration.
        if ($existingClient) {
            $this->clientRepository->update($registrationClient);
        } else {
            $this->clientRepository->add($registrationClient);
        }

        // Mark Request Object as used.
        try {
            $this->federationCache?->set(
                $requestObject->getJwtId(),
                $this->helpers->dateTime()->getSecondsToExpirationTime($requestObject->getExpirationTime()),
                self::KEY_REQUEST_OBJECT_JTI,
                $requestObject->getJwtId(),
            );
        } catch (Throwable $e) {
            $this->loggerService->error(
                'ClientRule: Error while trying to mark request object as used: ' . $e->getMessage(),
            );
        }

        // We will also update a result for RequestParameterRule (inject value from here), since the request object
        // is already resolved.
        $currentResultBag->add(new Result(RequestObjectRule::class, $requestObject->getPayload()));

        return $registrationClient;
    }

    protected function getGenericVciClient(): ClientEntityInterface
    {
        $client = $this->clientEntityFactory->getGenericForVci();
        if ($this->clientRepository->findById($client->getIdentifier()) === null) {
            $this->clientRepository->add($client);
        } else {
            $this->clientRepository->update($client);
        }

        return $client;
    }
}
