<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use DateInterval;
use DateTimeImmutable;
use DateTimeInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusIssuer;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\TermsOfUseTypesEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\TokenStatusList\StatusClaim;
use SimpleSAML\OpenID\VerifiableCredentials;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class CredentialIssuerCredentialController
{
    public const array SD_JWT_FORMAT_IDS = [
        CredentialFormatIdentifiersEnum::DcSdJwt->value,
        CredentialFormatIdentifiersEnum::VcSdJwt->value,
    ];

    /**
     * Bytes of randomness in the identifier a credential carries as its `jti`.
     *
     * The identifier is what revocation is keyed on, so it has to be unguessable: anyone able to work
     * out the identifier of a credential they were never issued could ask for it to be revoked. It is
     * also a URI, since the parsers enforce that, so the randomness is a suffix on a fixed base rather
     * than the whole value.
     */
    protected const int CREDENTIAL_ID_RANDOM_BYTES = 32;


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ResourceServer $resourceServer,
        protected readonly AccessTokenRepository $accessTokenRepository,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly PsrHttpBridge $psrHttpBridge,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly LoggerService $loggerService,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly UserRepository $userRepository,
        // Holds the DID facade factory rather than a built facade, so that the guard below is what
        // answers a deployment with Verifiable Credentials switched off. The container resolves every
        // argument here before this constructor body runs, and building the facade reads the DID
        // destination settings and instantiates the VCI cache adapter - which turned that 403 into a
        // 500 on a request this endpoint refuses outright. Nothing is built until there is a credential
        // to sign.
        protected readonly VciIssuerIdentityResolver $vciIssuerIdentityResolver,
        protected readonly VciIssuerIdentityRepository $vciIssuerIdentityRepository,
        protected readonly OpenId4VciProofValidator $openId4VciProofValidator,
        protected readonly VciContextResolver $vciContextResolver,
        protected readonly CredentialStatusIssuer $credentialStatusIssuer,
        protected readonly Helpers $helpers,
        protected readonly ErrorResponder $errorResponder,
    ) {
        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    /**
     * An OAuth error raised on the way is answered as a JSON error response carrying the exception's own
     * status. Among them is the resource server's 401 for an access token which is missing, invalid or
     * revoked; a token sent only in the query string is a missing one, since the resource server reads none
     * from there. Left to escape the controller, each of them reached the client as SimpleSAMLphp's HTML
     * error page with status 500.
     *
     * Every 401 this endpoint answers carries a challenge, whichever check made it a 401: HTTP requires one
     * of any 401 (RFC 9110 section 15.5.2), and RFC 6750 section 3 has a protected resource send one when the
     * access token is missing or does not authorize the request. Both schemes are challenged, as RFC 9449
     * section 7.2 recommends (OidcServerException::buildResourceChallenges()). A refused token is named in the
     * challenge of the scheme it was presented under (`error="invalid_token"`), and a request which carried none
     * gets both challenges with no error and no body (RFC 6750 section 3.1); these come with the refusal. A 401
     * from anywhere else gets both challenges with no error.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \ReflectionException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    public function credential(Request $request): Response
    {
        try {
            $response = $this->issueCredential($request);
        } catch (OAuthServerException $exception) {
            $response = $this->errorResponder->forExceptionJson($exception);
        }

        if ($response->getStatusCode() === 401 && !$response->headers->has('WWW-Authenticate')) {
            $response->headers->set(
                'WWW-Authenticate',
                OidcServerException::buildResourceChallenges(
                    null,
                    null,
                    $this->moduleConfig->getDpopSigningAlgorithms(),
                ),
            );
        }

        return $response;
    }


    /**
     * Refuses an access token which passed the resource server but can not buy a credential, as the resource
     * server refuses one (RFC 6750 section 3.1): `invalid_token`, with the error named in the challenge too, that
     * of the scheme the token was presented under (OidcServerException::buildResourceChallenges()).
     */
    protected function invalidTokenResponse(string $description, AccessTokenTypesEnum $scheme): Response
    {
        return $this->routes->newJsonErrorResponse(
            'invalid_token',
            $description,
            401,
            [
                'WWW-Authenticate' => OidcServerException::buildResourceChallenges(
                    $scheme,
                    'invalid_token',
                    $this->moduleConfig->getDpopSigningAlgorithms(),
                ),
            ],
        );
    }


    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \ReflectionException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function issueCredential(Request $request): Response
    {
        $this->loggerService->info('Verifiable Credential issuance request received.');
        $psrRequest = $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request);

        $requestData = $this->requestParamsResolver->getAllFromRequestBasedOnAllowedMethods(
            $psrRequest,
            [HttpMethodsEnum::POST],
        );

        $this->loggerService->debug(
            'CredentialIssuerCredentialController: Request data: ',
            $requestData,
        );

        $this->loggerService->debug('Verifying access token and authorizing request.');
        $authorization = $this->resourceServer->validateAuthenticatedRequest(
            $psrRequest,
            $this->routes->urlCredentialIssuerCredential(),
        );
        $scheme = AccessTokenTypesEnum::tryFrom(
            (string)$authorization->getAttribute(BearerTokenValidator::ATTRIBUTE_ACCESS_TOKEN_SCHEME),
        ) ?? AccessTokenTypesEnum::Bearer;

        $accessToken = $this->accessTokenRepository->findById(
            (string)$authorization->getAttribute('oauth_access_token_id'),
        );

        if (! $accessToken instanceof AccessTokenEntity) {
            $this->loggerService->error('Access token not found in repository.');
            return $this->invalidTokenResponse('Access token not found.', $scheme);
        }

        if ($accessToken->isRevoked()) {
            $this->loggerService->error('Access token is revoked.', ['accessTokenId' => $accessToken->getIdentifier()]);
            return $this->invalidTokenResponse('Access token is revoked.', $scheme);
        }

        if (
            ($flowType = $accessToken->getFlowTypeEnum()) === null ||
            $flowType->isVciFlow() === false
        ) {
            $this->loggerService->warning(
                'Access token is not intended for Verifiable Credential Issuance.',
                ['flowType' => $flowType?->value, 'accessTokenId' => $accessToken->getIdentifier()],
            );
            return $this->invalidTokenResponse(
                'Access token is not intended for verifiable credential issuance.',
                $scheme,
            );
        }

        // A token which can not buy a credential is refused as RFC 6750 section 3 has it (OpenID4VCI 1.0 section
        // 8.3.1.1): the fault is the token's, which no change to the Credential Request would mend.
        $issuerState = $accessToken->getIssuerState();
        if (
            !is_string($issuerState) &&
            ($accessToken->getFlowTypeEnum() === FlowTypeEnum::VciAuthorizationCode) &&
            !$this->isIssuedToRegisteredClient($accessToken)
        ) {
            $this->loggerService->error(
                'CredentialIssuerCredentialController::credential: Issuer state missing in access token issued ' .
                'to a client which is not registered.',
                ['accessTokenState' => $accessToken->getState()],
            );
            return $this->invalidTokenResponse('Issuer state missing in access token.', $scheme);
        }

        // An issuer state on the token is not checked again here. The token endpoint spent it when it exchanged
        // the code carrying it for this token (AuthCodeGrant), so the token can be used for as many credential
        // requests as its lifetime allows, like one which followed no offer (OpenID4VCI 1.0 section 14.3).

        if (
            isset($requestData[ClaimsEnum::CredentialConfigurationId->value]) &&
            isset($requestData[ClaimsEnum::CredentialIdentifier->value])
        ) {
            $this->loggerService->error(
                'CredentialIssuerCredentialController::credential: Credential configuration ID ' .
                '(credential_configuration_id) present in request together with credential identifier ' .
                '(credential_identifier).',
            );

            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Credential configuration ID must not be used together with credential identifier.',
                400,
            );
        }

        // Resolve the requested credential identifier.
        $resolvedCredentialIdentifier = null;

        /** @psalm-suppress MixedAssignment */
        $credentialIdentifier = $requestData[ClaimsEnum::CredentialIdentifier->value] ?? null;

        // If the `authorization_details` parameter was used in the grant flow, the credential request has to use
        // `credential_identifier` to request a specific credential. In this case `credential_configuration_id`
        // must not be present. A credential identifier names one the token response issued (OpenID4VCI 1.0
        // section 8.2), so one sent for a flow which used no `authorization_details`, and so was issued none,
        // is unknown rather than ignored.
        $authorizationDetails = $accessToken->getAuthorizationDetails();
        if ($authorizationDetails !== null || $credentialIdentifier !== null) {
            if (!is_string($credentialIdentifier)) {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Credential identifier missing in request.',
                );
                return $this->routes->newJsonErrorResponse(
                    'invalid_credential_request',
                    'Can not resolve credential identifier.',
                    400,
                );
            }

            $isCredentialIdentifierUsedInFlow = false;
            foreach ($authorizationDetails ?? [] as $authorizationDetail) {

                /** @psalm-suppress MixedAssignment */
                if (
                    !is_array($authorizationDetail) ||
                    !isset($authorizationDetail[ClaimsEnum::Type->value]) ||
                    $authorizationDetail[ClaimsEnum::Type->value] !== 'openid_credential' ||
                    !isset($authorizationDetail[ClaimsEnum::CredentialConfigurationId->value]) ||
                    !is_string(
                        $authorizationDetailCredentialConfigurationId =
                            $authorizationDetail[ClaimsEnum::CredentialConfigurationId->value],
                    )
                ) {
                    $this->loggerService->warning(
                        'CredentialIssuerCredentialController::credential: Unusable authorization detail.',
                        ['authorizationDetail' => $authorizationDetail],
                    );
                    continue;
                }

                if ($credentialIdentifier === $authorizationDetailCredentialConfigurationId) {
                    $this->loggerService->debug(
                        'Credential identifier matched with authorization detail.',
                        ['credentialIdentifier' => $credentialIdentifier],
                    );
                    $isCredentialIdentifierUsedInFlow = true;
                    break;
                }
            }

            if (!$isCredentialIdentifierUsedInFlow) {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Credential identifier not used in flow.',
                    ['credentialIdentifier' => $credentialIdentifier],
                );
                return $this->routes->newJsonErrorResponse(
                    'unknown_credential_identifier',
                    'Credential identifier not used in flow.',
                    400,
                );
            }

            $resolvedCredentialIdentifier = $credentialIdentifier;

            $this->loggerService->debug(
                'Resolved credential identifier from "credential_identifier" parameter.',
                ['resolvedCredentialIdentifier' => $resolvedCredentialIdentifier],
            );
        } else {
            $this->loggerService->debug(
                'No authorization details in the access token and no credential identifier in the request. ' .
                'Skipping resolution from "credential_identifier".',
            );
        }

        if (!is_string($resolvedCredentialIdentifier)) {
            $this->loggerService->debug('Resolving credential identifier from "credential_configuration_id".');

            /** @psalm-suppress MixedAssignment */
            $credentialConfigurationId = $requestData[ClaimsEnum::CredentialConfigurationId->value] ?? null;

            if (is_string($credentialConfigurationId)) {
                /** @psalm-suppress MixedAssignment */
                $resolvedCredentialIdentifier = $credentialConfigurationId;

                $this->loggerService->debug(
                    'Resolved credential identifier from "credential_configuration_id" parameter.',
                    ['resolvedCredentialIdentifier' => $resolvedCredentialIdentifier],
                );
            } else {
                $this->loggerService->warning('Credential identifier not provided in request parameters.');
            }
        }

        if (!is_string($resolvedCredentialIdentifier)) {
            $this->loggerService->warning(
                'CredentialIssuerCredentialController::credential: No credential identifier found in request. ' .
                'Falling back to resolution from format and credential type.',
            );

            $requestedCredentialFormatId = $requestData[ClaimsEnum::Format->value] ?? null;

            if (!is_string($requestedCredentialFormatId)) {
                $this->loggerService->error('Credential format missing in request (fallback resolution failed).');
                return $this->routes->newJsonErrorResponse(
                    'invalid_credential_request',
                    'Can not resolve credential format.',
                    400,
                );
            }

            if (
                !in_array($requestedCredentialFormatId, [
                    CredentialFormatIdentifiersEnum::JwtVcJson->value,
                    CredentialFormatIdentifiersEnum::DcSdJwt->value,
                    CredentialFormatIdentifiersEnum::VcSdJwt->value,
                ])
            ) {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Unsupported credential format.',
                    ['requestedCredentialFormatId' => $requestedCredentialFormatId],
                );
                return $this->routes->newJsonErrorResponse(
                    'unsupported_credential_type',
                    sprintf('Credential format ID "%s" is not supported.', $requestedCredentialFormatId),
                    400,
                );
            }

            $this->loggerService->debug(
                'Resolved requested credential format.',
                ['format' => $requestedCredentialFormatId],
            );

            $fallbackCredentialConfigurationId = null;

            // TODO mivanci Update this to newest draft.
            // Check per draft 14 (Sphereon wallet case).
            /** @psalm-suppress MixedAssignment */
            if (
                $requestedCredentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value &&
                is_array(
                    $credentialDefinitionType =
                        $requestData[ClaimsEnum::CredentialDefinition->value][ClaimsEnum::Type->value] ?? null,
                )
            ) {
                $this->loggerService->debug(
                    'Resolving configuration from credential definition types.',
                    ['types' => $credentialDefinitionType],
                );
                $fallbackCredentialConfigurationId =
                $this->moduleConfig->getVciCredentialConfigurationIdForCredentialDefinitionType(
                    $credentialDefinitionType,
                );
            } elseif (
                in_array($requestedCredentialFormatId, self::SD_JWT_FORMAT_IDS, true) &&
                is_string($vct = $requestData[ClaimsEnum::Vct->value] ?? null)
            ) {
                $this->loggerService->debug(
                    'Resolving configuration from VCT parameter.',
                    ['vct' => $vct],
                );
                $fallbackCredentialConfigurationId = $vct;
            }

            if (!is_string($fallbackCredentialConfigurationId)) {
                $this->loggerService->error('Fallback resolution failed to find a valid credential configuration.');
            } else {
                $this->loggerService->debug(
                    'Resolved credential identifier via fallback mechanism.',
                    ['resolvedCredentialIdentifier' => $fallbackCredentialConfigurationId],
                );

                $resolvedCredentialIdentifier = $fallbackCredentialConfigurationId;
            }
        }
        if (!is_string($resolvedCredentialIdentifier)) {
            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Can not resolve credential configuration ID.',
                400,
            );
        }

        $resolvedCredentialConfiguration = $this->moduleConfig->getVciCredentialConfiguration(
            $resolvedCredentialIdentifier,
        );
        $this->loggerService->debug('Resolved credential configuration.', [
            'identifier' => $resolvedCredentialIdentifier,
            'configuration' => $resolvedCredentialConfiguration,
        ]);
        if (!is_array($resolvedCredentialConfiguration)) {
            return $this->routes->newJsonErrorResponse(
                'unknown_credential_configuration',
                sprintf('Credential ID "%s" is not supported.', $resolvedCredentialIdentifier),
                400,
            );
        }

        // The credential has to be among what the token's scopes grant, whichever flow issued it. A configuration
        // requested through authorization_details is among them when it was granted: AuthCodeGrant adds those
        // ids to the scopes, and the token endpoint keeps only the scopes the client is registered for. A token
        // which followed a Credential Offer was granted no more than the offer offered: OfferedCredentialsRule
        // refuses a request for anything else, and PreAuthCodeGrant gives a pre-authorized token the offer's.
        if (!$this->isCredentialConfigurationGranted($accessToken, $resolvedCredentialIdentifier)) {
            $this->loggerService->error(
                'CredentialIssuerCredentialController::credential: Credential configuration not granted by the ' .
                'access token.',
                [
                    'credentialConfigurationId' => $resolvedCredentialIdentifier,
                    'accessTokenId' => $accessToken->getIdentifier(),
                ],
            );
            return $this->routes->newJsonErrorResponse(
                'insufficient_scope',
                'The access token does not grant the requested credential.',
                403,
            );
        }

        $credentialFormatId = $resolvedCredentialConfiguration[ClaimsEnum::Format->value] ?? null;
        if (!is_string($credentialFormatId)) {
            $this->loggerService->error(
                'CredentialIssuerCredentialController::credential: Credential format ID missing in ' .
                'resolved credential configuration.',
                ['resolvedCredentialConfiguration' => $resolvedCredentialConfiguration],
            );
            throw OidcServerException::serverError(
                'Credential format ID missing in resolved credential configuration (format is mandatory).',
            );
        }

        $userId = $accessToken->getUserIdentifier();
        if (!is_string($userId)) {
            throw OidcServerException::invalidRequest('User identifier not available in Access Token.');
        }
        $userEntity = $this->userRepository->getUserEntityByIdentifier($userId);
        if ($userEntity === null) {
            $this->loggerService->error('User entity not found.', ['userId' => $userId]);
            throw OidcServerException::invalidRequest('User not found.');
        }
        $this->loggerService->info('Issuing credential for user.', ['userId' => $userId]);

        // Every key proof is validated before anything at all is issued. Validating and issuing in one
        // pass would let a request whose last proof turns out to be bad still leave behind the Status
        // List entries its earlier proofs allocated, spent on credentials no wallet ever receives.
        try {
            $validatedProofs = $this->openId4VciProofValidator->validateRequest(
                $requestData,
                $this->moduleConfig->getVciCredentialBindingPolicyFor($resolvedCredentialIdentifier),
                $accessToken,
            );
        } catch (CredentialRequestException $credentialRequestException) {
            $this->loggerService->warning(
                'Credential request refused.',
                [
                    'error' => $credentialRequestException->getErrorCode(),
                    'reason' => $credentialRequestException->getMessage(),
                    'credentialConfigurationId' => $resolvedCredentialIdentifier,
                ],
            );

            return $this->routes->newJsonErrorResponse(
                $credentialRequestException->getErrorCode(),
                $credentialRequestException->getMessage(),
                400,
            );
        }

        $issuedCredentialsData = [];

        // Noted from inside the loop so that what is recorded afterwards is the identity credentials
        // were actually signed under, rather than what configuration said before any of them was.
        $issuerIdentity = null;

        // The OpenID Federation Entity Identifier a credential points a verifier at for trust
        // establishment (OpenID Fed DCP, Appendix B of DIIP v5). It is the issuer URL and not the
        // credential's `iss`, which the issuer identity mode may make a DID - and a DID has no Entity
        // Configuration to fetch, which is the gap the claim exists to bridge. Stated only while an
        // Entity Configuration is actually published at it: with federation off the well-known
        // endpoint answers 403, and naming it would send a verifier somewhere it can resolve nothing.
        $entityIdentifier = $this->moduleConfig->getFederationEnabled() ? $this->moduleConfig->getIssuer() : null;

        // The times every credential of this request states, read once and rounded (RFC 9901 section 10.1):
        // the credentials of a batch are issued in the same instant, and stating it to the second would let
        // verifiers link them. Issuance is rounded down and expiry up, the expiry from the moment itself
        // rather than from the rounded issuance, so that rounding never cuts a credential's configured
        // lifetime short and never issues one already expired.
        $now = new DateTimeImmutable();
        $timeClaimGranularity = $this->moduleConfig->getVciTimeClaimGranularity();
        $issuedAt = $this->helpers->dateTime()->floorTo($now, $timeClaimGranularity);
        $credentialTtl = $this->moduleConfig->getVciCredentialTtlFor($resolvedCredentialIdentifier);
        $expiresAt = $credentialTtl instanceof DateInterval ?
        $this->helpers->dateTime()->ceilTo($now->add($credentialTtl), $timeClaimGranularity) :
        null;

        foreach ($validatedProofs as $validatedProof) {
            // A configuration which issues credentials that are not bound to a holder key has no wallet
            // key to name here, so the subject is one this issuer derives from the authenticated user.
            $sub = $validatedProof?->getSubject() ??
            ($this->moduleConfig->getIssuer() . '/sub/' . $userId);

            $userAttributes = $userEntity->getClaims();

        // Get valid claim paths so we can check if the user attribute is allowed to be included in the credential,
        // as per the credential configuration supported configuration.
            $validClaimPaths = $this->moduleConfig->getVciValidCredentialClaimPathsFor($resolvedCredentialIdentifier);
            $this->loggerService->debug('Mapping user attributes to credential claims.', [
                'resolvedCredentialIdentifier' => $resolvedCredentialIdentifier,
                'validClaimPaths' => $validClaimPaths,
            ]);
        // Map user attributes to credential claims
            $credentialSubject = []; // For JwtVcJson
            $disclosureBag = $this->verifiableCredentials->disclosureBagFactory()->build(); // For DcSdJwt
            $attributeToCredentialClaimPathMap = $this->moduleConfig->getVciUserAttributeToCredentialClaimPathMapFor(
                $resolvedCredentialIdentifier,
            );
            $this->loggerService->debug('Using attribute to claim path map.', [
                'map' => $attributeToCredentialClaimPathMap,
            ]);
            /** @psalm-suppress MixedAssignment */
            foreach ($attributeToCredentialClaimPathMap as $mapEntry) {
                if (!is_array($mapEntry)) {
                    $this->loggerService->warning(
                        sprintf(
                            'Attribute to credential claim path map entry is not an array. Value was: %s',
                            var_export($mapEntry, true),
                        ),
                    );
                    continue;
                }

                $this->loggerService->debug('Processing attribute mapping entry.', ['entry' => $mapEntry]);

                $userAttributeName = key($mapEntry);
                if (!is_string($userAttributeName)) {
                    $this->loggerService->warning(
                        sprintf(
                            'User attribute name from map entry is not a string. Map entry was: %s',
                            var_export($mapEntry, true),
                        ),
                    );
                    continue;
                }

                $this->loggerService->debug(
                    'User attribute name: ' . $userAttributeName,
                );

            /** @psalm-suppress MixedAssignment */
                $credentialClaimPath = current($mapEntry);
                if (!is_array($credentialClaimPath)) {
                    $this->loggerService->warning(
                        sprintf(
                            'Credential claim path for user attribute name %s is not an array. Value was: %s',
                            $userAttributeName,
                            var_export($credentialClaimPath, true),
                        ),
                    );
                    continue;
                }
                $credentialClaimPath = array_filter($credentialClaimPath, 'is_string');
                if (!in_array($credentialClaimPath, $validClaimPaths)) {
                    $this->loggerService->warning(
                        'Attribute "%s" does not use one of valid credential claim paths.',
                        $mapEntry,
                    );
                    continue;
                }

                $this->loggerService->debug('Mapping attribute to claim path.', [
                    'attribute' => $userAttributeName,
                    'path' => $credentialClaimPath,
                ]);

                if (!isset($userAttributes[$userAttributeName])) {
                    $this->loggerService->warning(
                        'Attribute "%s" does not exist in user attributes.',
                        $mapEntry,
                    );
                    continue;
                }

            // Normalize to string for single array values.
            /** @psalm-suppress MixedAssignment */
                $attributeValue = is_array($userAttributes[$userAttributeName]) &&
                count($userAttributes[$userAttributeName]) === 1 ?
                reset($userAttributes[$userAttributeName]) :
                $userAttributes[$userAttributeName];

                if ($credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value) {
                    $this->loggerService->debug(
                        'JwtVcJson format detected, adding user attribute to credential subject.',
                    );
                    $this->verifiableCredentials->helpers()->arr()->setNestedValue(
                        $credentialSubject,
                        $attributeValue,
                        ...$credentialClaimPath,
                    );
                }

                if (in_array($credentialFormatId, self::SD_JWT_FORMAT_IDS, true)) {
                    $this->loggerService->debug('Adding attribute to SD-JWT disclosure bag.', [
                        'attribute' => $userAttributeName,
                        'format' => $credentialFormatId,
                    ]);

                // For now, we will only support disclosures for object properties.
                    $claimName = array_pop($credentialClaimPath);
                    if (!is_string($claimName)) {
                        $message = sprintf(
                            'Invalid credential claim path for user attribute name %s. Can not extract claim name.' .
                            ' Path was: %s',
                            $userAttributeName,
                            print_r($credentialClaimPath, true),
                        );
                        $this->loggerService->error($message);
                        continue;
                    }

                    $this->loggerService->debug('Claim name: ' . $claimName);

                    if (
                        $credentialFormatId === CredentialFormatIdentifiersEnum::VcSdJwt->value &&
                        !in_array(ClaimsEnum::Credential_Subject->value, $credentialClaimPath, true)
                    ) {
                        $this->loggerService->debug(
                            'VC SD JWT - adding credential subject to claim path for claim "%s".',
                        );
                        array_unshift($credentialClaimPath, ClaimsEnum::Credential_Subject->value);
                        $this->loggerService->debug(
                            'Credential claim path for credential subject: ' . print_r($credentialClaimPath, true),
                        );
                    }

                /** @psalm-suppress ArgumentTypeCoercion */
                    $disclosure = $this->verifiableCredentials->disclosureFactory()->build(
                        value: $attributeValue,
                        name: $claimName,
                        path: $credentialClaimPath,
                        saltBlacklist: $disclosureBag->salts(),
                    );

                    $disclosureBag->add($disclosure);
                }
            }

            // Make sure that the subject identifier is in credentialSubject claim.
            $this->setCredentialClaimValue(
                $credentialSubject,
                [ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value],
                $sub,
            );

            // The same key issuer metadata advertised, and the same one the credential's Status List Token
            // is signed with. Asked for by name so those three can not drift apart.
            $vciSignatureKeyPair = $this->moduleConfig->getActiveVciSignatureKeyPair();

            $signingKey = $vciSignatureKeyPair->getKeyPair()->getPrivateKey();

            // How the credential says who issued it and which key signed it. Resolved from the
            // configured identity and the key pair in hand rather than derived here, so that the `iss`
            // claim and the `kid` header can not be built under different rules.
            $issuerIdentity = $this->vciIssuerIdentityResolver->resolve(
                $this->moduleConfig->getVciIssuerIdentifier(),
                $vciSignatureKeyPair,
            );

            // Unguessable rather than sequential or time based, since this is what revocation is keyed
            // on. Still in URI form, because the credential parsers enforce that of a `jti`.
            $vcId = $this->moduleConfig->getIssuer() . '/vc/' .
            $this->helpers->random()->getIdentifier(self::CREDENTIAL_ID_RANDOM_BYTES);
            $signatureAlgorithm = $vciSignatureKeyPair->getSignatureAlgorithm();

            // Inside the loop rather than outside it: a request carrying several proofs is issued
            // several credentials, and each one needs an entry of its own to be revocable separately.
            try {
                $statusClaim = $this->credentialStatusIssuer->issueFor(
                    $resolvedCredentialIdentifier,
                    $vcId,
                    $userId,
                    $expiresAt,
                );
            } catch (Throwable $exception) {
                // Refusing to issue is the point. This configuration is set up to produce revocable
                // credentials, and one issued without a status claim could never be withdrawn -- with
                // nothing on it to say that it is the exception.
                $this->loggerService->error(
                    'Could not allocate a Status List entry, so no credential was issued.',
                    [
                        'credentialConfigurationId' => $resolvedCredentialIdentifier,
                        'error' => $exception->getMessage(),
                    ],
                );

                return $this->routes->newJsonErrorResponse(
                    'server_error',
                    'Unable to issue a revocable credential at this time.',
                    500,
                );
            }

            $this->loggerService->info('Signing and issuing verifiable credential.', [
                'vcId' => $vcId,
                'format' => $credentialFormatId,
                'issuer' => $issuerIdentity->getIssuer(),
                'issuerKeyId' => $issuerIdentity->getKeyId(),
                'sub' => $sub,
                'algorithm' => $signatureAlgorithm->value,
                'expiresAt' => $expiresAt?->getTimestamp(),
                'hasStatusClaim' => $statusClaim instanceof StatusClaim,
            ]);

            // Both are merged into every format below. The status claim sits at the top level of the
            // payload, which is where the Status List specification puts it for a JOSE Referenced
            // Token, and not inside the credential body of the W3C formats.
            /** @var array<non-empty-string,mixed> $commonClaims */
            $commonClaims = $statusClaim instanceof StatusClaim ? $statusClaim->jsonSerialize() : [];

            if ($expiresAt instanceof DateTimeImmutable) {
                $commonClaims[ClaimsEnum::Exp->value] = $expiresAt->getTimestamp();
            }

            // Stated once for every format, rather than in each branch which builds one. `cnf` is where
            // a verifier reads what a credential is held by, so a format branch which omits it hands
            // out credentials that look unbound however carefully the proof behind them was checked -
            // which is what happened to this format and to inline-key proofs, each for the whole time
            // the claim was assembled separately in the branches that happened to have it.
            $confirmation = $validatedProof?->getConfirmation();

            if ($confirmation !== null) {
                $commonClaims[ClaimsEnum::Cnf->value] = $confirmation;
            }

            $verifiableCredential = null;

            if ($credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value) {
                $verifiableCredentialBody = [
                    ClaimsEnum::AtContext->value => [
                        AtContextsEnum::W3Org2018CredentialsV1->value,
                    ],
                    /** @psalm-suppress MixedArrayAccess */
                    ClaimsEnum::Type->value =>
                        $resolvedCredentialConfiguration[ClaimsEnum::CredentialDefinition->value]
                        [ClaimsEnum::Type->value] ?? [
                            CredentialTypesEnum::VerifiableCredential->value,
                            $resolvedCredentialIdentifier,
                        ],
                        //ClaimsEnum::Issuer->value => $this->moduleConfig->getIssuer(),
                        ClaimsEnum::Issuer->value => $issuerIdentity->getIssuer(),
                        ClaimsEnum::Issuance_Date->value => $issuedAt->format(DateTimeInterface::RFC3339),
                        ClaimsEnum::Id->value => $vcId,
                        ClaimsEnum::Credential_Subject->value =>
                        $credentialSubject[ClaimsEnum::Credential_Subject->value] ?? [],
                ];

                // Stated in the credential body as well as in the JWT `exp` claim above, mirroring the
                // issuance date, which this format already states as both `iat` and `issuanceDate`.
                if ($expiresAt instanceof DateTimeImmutable) {
                    $verifiableCredentialBody[ClaimsEnum::Expiration_Date->value] =
                    $expiresAt->format(DateTimeInterface::RFC3339);
                }

                // A W3C VCDM credential names its federation in the data model's own vocabulary, inside
                // the credential body, rather than as a JWT claim beside it.
                if ($entityIdentifier !== null) {
                    $verifiableCredentialBody[ClaimsEnum::Terms_Of_Use->value] =
                    $this->openIdFederationTermsOfUse($entityIdentifier);
                }

                $verifiableCredential = $this->verifiableCredentials->jwtVcJsonFactory()->fromData(
                    $signingKey,
                    $signatureAlgorithm,
                    array_merge(
                        [
                        ClaimsEnum::Vc->value => $verifiableCredentialBody,
                        //ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                        ClaimsEnum::Iss->value => $issuerIdentity->getIssuer(),
                        ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                        ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                        ClaimsEnum::Sub->value => $sub,
                        ClaimsEnum::Jti->value => $vcId,
                        ],
                        $commonClaims,
                    ),
                    [
                    ClaimsEnum::Kid->value => $issuerIdentity->getKeyId(),
                    ],
                );
            }

            if ($credentialFormatId === CredentialFormatIdentifiersEnum::DcSdJwt->value) {
                // A credential bound to a key names its holder by `cnf` alone. The subject a key proof
                // resolves to is the DID of its key: `cnf.kid` already names it, as a DID URL, or, for a key
                // sent inline, it is a `did:jwk` made from that key, so the credentials of a batch would
                // each carry their own where OpenID4VCI 1.0 section 3.3.2 has them share one Credential
                // Dataset. SD-JWT VC (draft 13, section 3.2.2.2) asks for no binding between `sub` and
                // `cnf`. An unbound credential keeps the subject this issuer derives from the user.
                $sdJwtPayload = array_merge(
                    [
                    ClaimsEnum::Iss->value => $issuerIdentity->getIssuer(),
                    ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                    ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                    ],
                    $confirmation === null ? [ClaimsEnum::Sub->value => $sub] : [],
                    [
                    ClaimsEnum::Jti->value => $vcId,
                    ClaimsEnum::Vct->value => $resolvedCredentialIdentifier,
                    ],
                    $commonClaims,
                );

                // An SD-JWT VC has no data model vocabulary for this, so it is a claim beside `iss`.
                if ($entityIdentifier !== null) {
                    $sdJwtPayload[ClaimsEnum::Fed->value] = $entityIdentifier;
                }

                $verifiableCredential = $this->verifiableCredentials->sdJwtVcFactory()->fromData(
                    $signingKey,
                    $signatureAlgorithm,
                    $sdJwtPayload,
                    [
                    ClaimsEnum::Kid->value => $issuerIdentity->getKeyId(),
                    ],
                    disclosureBag: $disclosureBag,
                );
            }

            if ($credentialFormatId === CredentialFormatIdentifiersEnum::VcSdJwt->value) {
                $atContext = $this->vciContextResolver->resolve(
                    $resolvedCredentialIdentifier,
                    $resolvedCredentialConfiguration,
                );

                $sdJwtPayload = array_merge(
                    [
                    ClaimsEnum::AtContext->value => $atContext,
                    ClaimsEnum::Id->value => $vcId,
                    /** @psalm-suppress MixedArrayAccess */
                    ClaimsEnum::Type->value =>
                        $resolvedCredentialConfiguration[ClaimsEnum::CredentialDefinition->value]
                        [ClaimsEnum::Type->value] ?? [
                            CredentialTypesEnum::VerifiableCredential->value,
                            $resolvedCredentialIdentifier,
                        ],
                        ClaimsEnum::Issuer->value => $issuerIdentity->getIssuer(),
                        ClaimsEnum::ValidFrom->value => $issuedAt->format(DateTimeInterface::RFC3339),
                        ClaimsEnum::Credential_Subject->value =>
                        $credentialSubject[ClaimsEnum::Credential_Subject->value] ?? [],
                        ClaimsEnum::Iss->value => $issuerIdentity->getIssuer(),
                        ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                        ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                        ClaimsEnum::Sub->value => $sub,
                        ClaimsEnum::Jti->value => $vcId,
                    ],
                    $commonClaims,
                );

                // The Verifiable Credentials Data Model 2.0 names the end of a credential's validity
                // `validUntil`, alongside the `validFrom` above, so this format states it both ways.
                if ($expiresAt instanceof DateTimeImmutable) {
                    $sdJwtPayload[ClaimsEnum::ValidUntil->value] = $expiresAt->format(DateTimeInterface::RFC3339);
                }

                // This is the W3C data model secured as an SD-JWT rather than an SD-JWT VC, so it names
                // its federation the way the data model does, and the payload is the credential body.
                if ($entityIdentifier !== null) {
                    $sdJwtPayload[ClaimsEnum::Terms_Of_Use->value] =
                    $this->openIdFederationTermsOfUse($entityIdentifier);
                }

                $verifiableCredential = $this->verifiableCredentials->vcSdJwtFactory()->fromData(
                    $signingKey,
                    $signatureAlgorithm,
                    $sdJwtPayload,
                    [
                    ClaimsEnum::Kid->value => $issuerIdentity->getKeyId(),
                    ],
                    disclosureBag: $disclosureBag,
                );
            }
            if ($verifiableCredential === null) {
                throw new OpenIdException('Invalid credential format ID.');
            }

            $token = $verifiableCredential->getToken();
            $issuedCredentialsData[] = ['credential' => $token];
            $this->loggerService->debug(
                'Verifiable credential issued successfully.',
                ['token' => substr($token, 0, 20) . '...'],
                //['token' => $token],
            );
        }

        // Note which identity this deployment has now issued under, so that a later change to it can be
        // reported rather than only discovered by whoever fails to verify an older credential. Recorded
        // after the fact and only when something was actually issued, since an identity nothing was
        // signed under obliges this deployment to nothing.
        if ($issuedCredentialsData !== [] && $issuerIdentity instanceof VciIssuerIdentity) {
            try {
                $this->vciIssuerIdentityRepository->recordUsage($issuerIdentity);
            } catch (Throwable $throwable) {
                // Deliberately not fatal, unlike the Status List allocation above. The credential is
                // signed and valid whether or not this was written; all that is lost is the ability to
                // warn about a later identity change, so failing the request would trade a real
                // credential for a diagnostic.
                $this->loggerService->error(
                    'Could not record the issuer identity credentials were issued under.',
                    ['issuer' => $issuerIdentity->getIssuer(), 'error' => $throwable->getMessage()],
                );
            }
        }

        $this->loggerService->info('Credential issuance request completed successfully.', [
            'issuedCount' => count($issuedCredentialsData),
        ]);

        return $this->routes->newJsonResponse(
            [
                'credentials' => $issuedCredentialsData,
            ],
        );
    }


    /**
     * Whether the access token was issued to a registered client, which is what an authorization code token
     * without an issuer_state needs to be. A wallet which starts the flow on its own sends no issuer_state, and
     * the credential scopes it was granted are ones its registration allows (ScopeRepository::finalizeScopes());
     * the credential it asks for is then checked against them (isCredentialConfigurationGranted()).
     * The generic client stands in for wallets which are not registered, and ClientRule falls back to it only
     * for a request carrying an issuer_state, so its tokens always need one to be redeemed here.
     */
    protected function isIssuedToRegisteredClient(AccessTokenEntity $accessToken): bool
    {
        $client = $accessToken->getClient();

        return $client instanceof ClientEntityInterface && !$client->isGeneric();
    }


    protected function isCredentialConfigurationGranted(
        AccessTokenEntity $accessToken,
        string $credentialConfigurationId,
    ): bool {
        foreach ($accessToken->getScopes() as $scope) {
            if ($scope->getIdentifier() === $credentialConfigurationId) {
                return true;
            }
        }

        return false;
    }


    /**
     * Helper method to set a claim value at a path. Supports creating nested arrays dynamically.
     * @psalm-suppress UnusedVariable, MixedAssignment
     * @param array-key[] $path
     */
    protected function setCredentialClaimValue(array &$claims, array $path, mixed $value): void
    {
        $temp = &$claims;

        foreach ($path as $key) {
            if (!is_array($temp)) {
                $temp = [];
            }

            $temp[$key] ??= [];

            $temp = &$temp[$key];
        }

        // If the value is an array and holds only one element, we will set the value directly.
        if (is_array($value) && count($value) === 1) {
            $temp = $value[0];
        } else {
            $temp = $value;
        }
    }


    /**
     * The `termsOfUse` entry OpenID Fed DCP has a W3C VCDM credential carry, naming the Entity Identifier
     * a verifier resolves the Issuer's Trust Chain from.
     *
     * A single entry rather than a list of one. The data model allows either, and the profile's own
     * example states the one entry bare.
     *
     * @param non-empty-string $entityIdentifier
     * @return array{type: non-empty-string, policyId: non-empty-string}
     */
    protected function openIdFederationTermsOfUse(string $entityIdentifier): array
    {
        return [
            ClaimsEnum::Type->value => TermsOfUseTypesEnum::OpenIdFederation->value,
            ClaimsEnum::Policy_Id->value => $entityIdentifier,
        ];
    }
}
