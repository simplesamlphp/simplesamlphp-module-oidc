<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Exceptions\OpenId4VciProofException;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerCredentialController
{
    public const array SD_JWT_FORMAT_IDS = [
        CredentialFormatIdentifiersEnum::DcSdJwt->value,
        CredentialFormatIdentifiersEnum::VcSdJwt->value,
    ];

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
        protected readonly Did $did,
        protected readonly IssuerStateRepository $issuerStateRepository,
        protected readonly NonceService $nonceService,
    ) {
        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \ReflectionException
     * @throws OpenIdException
     */
    public function credential(Request $request): Response
    {
        $this->loggerService->debug('CredentialIssuerCredentialController::credential');

        $requestData = $this->requestParamsResolver->getAllFromRequestBasedOnAllowedMethods(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
            [HttpMethodsEnum::POST],
        );

        $this->loggerService->debug(
            'CredentialIssuerCredentialController: Request data: ',
            $requestData,
        );

        $authorization = $this->resourceServer->validateAuthenticatedRequest(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
        );

        $accessToken = $this->accessTokenRepository->findById(
            (string)$authorization->getAttribute('oauth_access_token_id'),
        );

        if (! $accessToken instanceof AccessTokenEntity) {
            return $this->routes->newJsonErrorResponse(
                'invalid_token',
                'Access token not found.',
                401,
            );
        }

        if ($accessToken->isRevoked()) {
            return $this->routes->newJsonErrorResponse(
                'invalid_token',
                'Access token is revoked.',
                401,
            );
        }

        if (
            ($flowType = $accessToken->getFlowTypeEnum()) === null ||
            $flowType->isVciFlow() === false
        ) {
            $this->loggerService->warning(
                'CredentialIssuerCredentialController::credential: Access token is not intended for Verifiable' .
                ' Credential Issuance.',
                ['accessTokenState' => $accessToken->getState()],
            );
            return $this->routes->newJsonErrorResponse(
                'invalid_token',
                'Access token is not intended for verifiable credential issuance.',
                401,
            );
        }

        $issuerState = $accessToken->getIssuerState();
        if (
            !is_string($issuerState) &&
            ($accessToken->getFlowTypeEnum() === FlowTypeEnum::VciAuthorizationCode)
        ) {
            $this->loggerService->error(
                'CredentialIssuerCredentialController::credential: Issuer state missing in access token.',
                ['accessTokenState' => $accessToken->getState()],
            );
            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Issuer state missing in access token.',
                401,
            );
        }

        if (is_string($issuerState) && $this->issuerStateRepository->findValid($issuerState) === null) {
            $this->loggerService->warning(
                'CredentialIssuerCredentialController::credential: Issuer state not valid.',
                ['issuerState' => $issuerState],
            );
            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Issuer state not valid.',
                401,
            );
        }

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

        // If the `authorization_details` parameter was used in the grant flow, the credential request has to use
        // `credential_identifier` to request a specific credential. In this case `credential_configuration_id`
        // must not be present.
        if (($authorizationDetails = $accessToken->getAuthorizationDetails()) !== null) {
            $credentialIdentifier = $requestData[ClaimsEnum::CredentialIdentifier->value] ?? null;

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
            foreach ($authorizationDetails as $authorizationDetail) {

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
                        'CredentialIssuerCredentialController::credential: Credential identifier used in flow.',
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
                    'invalid_credential_request',
                    'Credential identifier not used in flow.',
                    400,
                );
            }

            $resolvedCredentialIdentifier = $credentialIdentifier;

            $this->loggerService->debug(
                'CredentialIssuerCredentialController::credential: Resolved credential identifier from ' .
                'credential_identifier parameter.',
                ['resolvedCredentialIdentifier' => $resolvedCredentialIdentifier],
            );
        } else {
            $this->loggerService->debug(
                'CredentialIssuerCredentialController::credential: No authorization details found in access' .
                ' token. Skipping credential identifier resolution from credential_identifier parameter.',
            );
        }

        if (!is_string($resolvedCredentialIdentifier)) {
            $this->loggerService->debug(
                'CredentialIssuerCredentialController::credential: Resolving credential identifier from ' .
                'credential_configuration_id parameter.',
            );

            /** @psalm-suppress MixedAssignment */
            $credentialConfigurationId = $requestData[ClaimsEnum::CredentialConfigurationId->value] ?? null;

            if (is_string($credentialConfigurationId)) {
                /** @psalm-suppress MixedAssignment */
                $resolvedCredentialIdentifier = $credentialConfigurationId;

                $this->loggerService->debug(
                    'CredentialIssuerCredentialController::credential: Resolved credential identifier from ' .
                    'credential_configuration_id parameter.',
                    ['resolvedCredentialIdentifier' => $resolvedCredentialIdentifier],
                );
            } else {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Credential configuration ID missing in ' .
                    'request.',
                );
            }
        }

        if (!is_string($resolvedCredentialIdentifier)) {
            $this->loggerService->warning(
                'CredentialIssuerCredentialController::credential: No credential identifier found in request. ' .
                'Falling back to resolution from format and credential type.',
            );

            $requestedCredentialFormatId = $requestData[ClaimsEnum::Format->value] ?? null;

            if (!is_string($requestedCredentialFormatId)) {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Credential format missing in request.',
                );
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
                'CredentialIssuerCredentialController::credential: Resolved credential format.',
                ['requestedCredentialFormatId' => $requestedCredentialFormatId],
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
                    'CredentialIssuerCredentialController::credential: Resolving credential configuration ID ' .
                    'from credential definition type.',
                    ['credentialDefinitionType' => $credentialDefinitionType],
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
                    'CredentialIssuerCredentialController::credential: Resolving credential configuration ID ' .
                    'from VCT.',
                    ['vct' => $vct],
                );
                $fallbackCredentialConfigurationId = $vct;
            }

            if (!is_string($fallbackCredentialConfigurationId)) {
                $this->loggerService->error(
                    'CredentialIssuerCredentialController::credential: Could not resolve credential from ' .
                    'format and credential type.',
                );
            } else {
                $this->loggerService->debug(
                    'CredentialIssuerCredentialController::credential: Resolved credential configuration ID ' .
                    'from format and credential type.',
                    ['fallbackCredentialConfigurationId' => $fallbackCredentialConfigurationId],
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
        if (!is_array($resolvedCredentialConfiguration)) {
            return $this->routes->newJsonErrorResponse(
                'unsupported_credential_type',
                sprintf('Credential ID "%s" is not supported.', $resolvedCredentialIdentifier),
                400,
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
            throw OidcServerException::invalidRequest('User not found.');
        }

        // Placeholder sub identifier. Will do if proof is not provided.
        $sub = $this->moduleConfig->getIssuer() . '/sub/' . $userId;

        $proof = null;
        // Validate proof, if provided.
        // TODO mivanci consider making proof mandatory (in issuer metadata).
        /** @psalm-suppress MixedAssignment */
        if (
            isset($requestData['proof']['proof_type']) &&
            isset($requestData['proof']['jwt']) &&
            $requestData['proof']['proof_type'] === 'jwt' &&
            is_string($proofJwt = $requestData['proof']['jwt']) &&
            $proofJwt !== ''
        ) {
            $this->loggerService->debug('Verifying proof JWT: ' . $proofJwt);

            try {
                /**
                 * Sample proof structure:
                 * 'proof' =>
                 * array (
                 * 'proof_type' => 'jwt',
                 * 'jwt' => 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JyU2ZYMkJVeHNVaW5QbVA3QUVzZEN4OWpQYlV0ZkIzWXN2MTd4TGpyZkMxeDNVZmlMTWtyeWdTZDJMeWltQ3RGejhHWlBqOFFrMUJFU0F6M21LWGRCTEpuUHNNQ0R4Nm9QNjNuZVpmR1NKelF5SjRLVlN6Nmt4UTJQOTE4NGdXS1FnI3oyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnJTZlgyQlV4c1VpblBtUDdBRXNkQ3g5alBiVXRmQjNZc3YxN3hManJmQzF4M1VmaUxNa3J5Z1NkMkx5aW1DdEZ6OEdaUGo4UWsxQkVTQXozbUtYZEJMSm5Qc01DRHg2b1A2M25lWmZHU0p6UXlKNEtWU3o2a3hRMlA5MTg0Z1dLUWcifQ.eyJhdWQiOiJodHRwczovL2lkcC5taXZhbmNpLmluY3ViYXRvci5oZXhhYS5ldSIsImlhdCI6MTc0ODUxNDE0NywiZXhwIjoxNzQ4NTE0ODA3LCJpc3MiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnJTZlgyQlV4c1VpblBtUDdBRXNkQ3g5alBiVXRmQjNZc3YxN3hManJmQzF4M1VmaUxNa3J5Z1NkMkx5aW1DdEZ6OEdaUGo4UWsxQkVTQXozbUtYZEJMSm5Qc01DRHg2b1A2M25lWmZHU0p6UXlKNEtWU3o2a3hRMlA5MTg0Z1dLUWciLCJqdGkiOiJiMmNlZDQ2Yi0zOWNiLTRkZDAtYmQxZS1hNzY5ZWNlOWUxMTIifQ.SPdMSnrfF8ybhfYluzz5OrfWJQDOpCu7-of8zVbp5UR89GaB7j14Egext1h9pYgl6JwIP8zibUjTSc8JLVYuvA',
                 * ),
                 *
                 * Sphereon proof in credential request
                 * {
                 * "typ": "openid4vci-proof+jwt",
                 * "alg": "ES256",
                 * "kid": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrSfX2BUxsUinPmP7AEsdCx9jPbUtfB3Ysv17xLjrfC1x3UfiLMkrygSd2LyimCtFz8GZPj8Qk1BESAz3mKXdBLJnPsMCDx6oP63neZfGSJzQyJ4KVSz6kxQ2P9184gWKQg#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrSfX2BUxsUinPmP7AEsdCx9jPbUtfB3Ysv17xLjrfC1x3UfiLMkrygSd2LyimCtFz8GZPj8Qk1BESAz3mKXdBLJnPsMCDx6oP63neZfGSJzQyJ4KVSz6kxQ2P9184gWKQg"
                 * }
                 * {
                 * "aud": "https://idp.mivanci.incubator.hexaa.eu",
                 * "iat": 1748514147,
                 * "exp": 1748514807,
                 * "iss": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrSfX2BUxsUinPmP7AEsdCx9jPbUtfB3Ysv17xLjrfC1x3UfiLMkrygSd2LyimCtFz8GZPj8Qk1BESAz3mKXdBLJnPsMCDx6oP63neZfGSJzQyJ4KVSz6kxQ2P9184gWKQg",
                 * "jti": "b2ced46b-39cb-4dd0-bd1e-a769ece9e112"
                 * }
                 */
                $proof = $this->verifiableCredentials->openId4VciProofFactory()->fromToken($proofJwt);
                (in_array($this->moduleConfig->getIssuer(), $proof->getAudience())) ||
                throw new OpenId4VciProofException('Invalid Proof audience.');

                $jwk = $proof->getJsonWebKey();
                $resolvedDid = null;

                if (is_array($jwk)) {
                    $resolvedDid = $this->did->didJwkResolver()->generateDidJwkFromJwk($jwk);
                } else {
                    $kid = $proof->getKeyId();
                    if (is_string($kid) && str_starts_with($kid, 'did:key:z')) {
                        // The fragment (#z2dmzD...) typically points to a specific verification method within the DID's
                        // context. For did:key, since the DID is the key, this fragment often just refers to the key
                        // itself.
                        ($resolvedDid = strtok($kid, '#')) || throw new OpenId4VciProofException(
                            'Error getting did:key without fragment. Value was: ' . $kid,
                        );

                        $jwk = $this->did->didKeyResolver()->extractJwkFromDidKey($resolvedDid);
                    } elseif (is_string($kid) && str_starts_with($kid, 'did:jwk:')) {
                        ($resolvedDid = strtok($kid, '#')) || throw new OpenId4VciProofException(
                            'Error getting did:jwk without fragment. Value was: ' . $kid,
                        );

                        $jwk = $this->did->didJwkResolver()->extractJwkFromDidJwk($resolvedDid);
                    }
                }

                if ($jwk !== null && $resolvedDid !== null) {
                    $proof->verifyWithKey($jwk);

                    $this->loggerService->debug('Proof verified successfully using ' . $resolvedDid);

                    // Verify nonce
                    $nonce = $proof->getNonce();
                    if (is_string($nonce) && $nonce !== '') {
                        $this->loggerService->debug('Proof nonce: ' . $nonce);

                        if (!$this->nonceService->validateNonce($nonce)) {
                            $this->loggerService->warning('Proof nonce is invalid or expired. Nonce was: ' . $nonce);
                            return $this->routes->newJsonErrorResponse(
                                error: 'invalid_nonce',
                                description: 'c_nonce is invalid or expired.',
                                httpCode: 400,
                            );
                        }

                        $this->loggerService->debug('Proof nonce validated successfully.');
                    } else {
                        $this->loggerService->warning('Nonce not present in proof, skipping nonce validation.');
                    }

                    // Set it as a subject identifier (bind it).
                    $sub = $resolvedDid;
                } else {
                    $this->loggerService->warning(
                        'Proof currently not supported (no did:key:z or did:jwk). ',
                        ['header' => $proof->getHeader(), 'payload' => $proof->getPayload()],
                    );
                    // TODO mivanci Consider adding support for other proof keys, like in sample for Lissi ('jwk')
                    /**
                     * 'header' =>
                     * array (
                     * 'alg' => 'ES256',
                     * 'typ' => 'openid4vci-proof+jwt',
                     * 'jwk' =>
                     * array (
                     * 'kty' => 'EC',
                     * 'crv' => 'P-256',
                     * 'x' => '7d1peDK5BTcnw45yGrRHcJJOxYrEj2sOvBnIXRyhxEM',
                     * 'y' => 'Z5x8pVp85PouIYkvQT2eJWZP3YgfUXPc6BIhJ2pETbM',
                     * ),
                     * ),
                     * 'payload' =>
                     * array (
                     * 'aud' => 'https://idp.mivanci.incubator.hexaa.eu',
                     * 'nonce' => NULL,
                     * 'iat' => 1758102462,
                     * 'iss' => '9c481dc3-2ad0-4fe0-881d-c32ad02fe0fc',
                     * ),
                     * )
                     */
                }
            } catch (\Exception $e) {
                $message = 'Error processing proof JWT: ' . $e->getMessage();
                $this->loggerService->error($message);
                return $this->routes->newJsonErrorResponse(
                    'invalid_proof',
                    $message,
                    400,
                );
            }
        }

        $userAttributes = $userEntity->getClaims();

        // Get valid claim paths so we can check if the user attribute is allowed to be included in the credential,
        // as per the credential configuration supported configuration.
        $validClaimPaths = $this->moduleConfig->getVciValidCredentialClaimPathsFor($resolvedCredentialIdentifier);
        $this->loggerService->debug(
            'CredentialIssuerCredentialController::credential: Valid claim paths for credential configuration ',
            ['validClaimPaths' => $validClaimPaths],
        );
        // Map user attributes to credential claims
        $credentialSubject = []; // For JwtVcJson
        $disclosureBag = $this->verifiableCredentials->disclosureBagFactory()->build(); // For DcSdJwt
        $attributeToCredentialClaimPathMap = $this->moduleConfig->getVciUserAttributeToCredentialClaimPathMapFor(
            $resolvedCredentialIdentifier,
        );
        $this->loggerService->debug(
            'CredentialIssuerCredentialController::credential: Attribute to credential claim path map',
            ['attributeToCredentialClaimPathMap' => $attributeToCredentialClaimPathMap],
        );
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

            $this->loggerService->debug(
                'Map entry: ',
                ['mapEntry' => $mapEntry],
            );

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

            $this->loggerService->debug(
                'Credential claim path',
                ['credentialClaimPath' => $credentialClaimPath],
            );

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
                $this->loggerService->debug('JwtVcJson format detected, adding user attribute to credential subject.');
                $this->verifiableCredentials->helpers()->arr()->setNestedValue(
                    $credentialSubject,
                    $attributeValue,
                    ...$credentialClaimPath,
                );
            }

            if (in_array($credentialFormatId, self::SD_JWT_FORMAT_IDS, true)) {
                $this->loggerService->debug(
                    'CredentialIssuerCredentialController::credential: Processing SD JWT credential format ID '
                    . $credentialFormatId,
                );

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
                    $this->loggerService->debug('VC SD JWT - adding credential subject to claim path for claim "%s".');
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

        // TODO mivanci Add support for multiple signature key pairs. For now, we only support (first) one.
        $vciSignatureKeyPair = $this->moduleConfig
            ->getVciSignatureKeyPairBag()
            ->getFirstOrFail();

        $signingKey = $vciSignatureKeyPair->getKeyPair()->getPrivateKey();

        $publicKey = $vciSignatureKeyPair->getKeyPair()->getPublicKey();

        $issuerDid = $this->did->didJwkResolver()->generateDidJwkFromJwk($publicKey->jwk()->all());

        $issuedAt = new \DateTimeImmutable();

        $vcId = $this->moduleConfig->getIssuer() . '/vc/' . uniqid();
        $signatureAlgorithm = $vciSignatureKeyPair->getSignatureAlgorithm();

        $verifiableCredential = null;

        if ($credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value) {
            $verifiableCredential = $this->verifiableCredentials->jwtVcJsonFactory()->fromData(
                $signingKey,
                $signatureAlgorithm,
                [
                    ClaimsEnum::Vc->value => [
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
                            ClaimsEnum::Issuer->value => $issuerDid,
                            ClaimsEnum::Issuance_Date->value => $issuedAt->format(\DateTimeInterface::RFC3339),
                            ClaimsEnum::Id->value => $vcId,
                            ClaimsEnum::Credential_Subject->value =>
                            $credentialSubject[ClaimsEnum::Credential_Subject->value] ?? [],
                    ],
                    //ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                    ClaimsEnum::Iss->value => $issuerDid,
                    ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                    ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                    ClaimsEnum::Sub->value => $sub,
                    ClaimsEnum::Jti->value => $vcId,
                ],
                [
                    ClaimsEnum::Kid->value => $issuerDid . '#0',
                ],
            );
        }

        if ($credentialFormatId === CredentialFormatIdentifiersEnum::DcSdJwt->value) {
            $sdJwtPayload = [
                ClaimsEnum::Iss->value => $issuerDid,
                ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Sub->value => $sub,
                ClaimsEnum::Jti->value => $vcId,
                ClaimsEnum::Vct->value => $resolvedCredentialIdentifier,
            ];

            if ($proof instanceof OpenId4VciProof && is_string($proofKeyId = $proof->getKeyId())) {
                $sdJwtPayload[ClaimsEnum::Cnf->value] = [
                    ClaimsEnum::Kid->value => $proofKeyId,
                ];
            }

            $verifiableCredential = $this->verifiableCredentials->sdJwtVcFactory()->fromData(
                $signingKey,
                $signatureAlgorithm,
                $sdJwtPayload,
                [
                    ClaimsEnum::Kid->value => $issuerDid . '#0',
                ],
                disclosureBag: $disclosureBag,
            );
        }

        if ($credentialFormatId === CredentialFormatIdentifiersEnum::VcSdJwt->value) {
            // Always start with the VCDM 2.0 base context URL (mandatory).
            $atContext = [AtContextsEnum::W3OrgNsCredentialsV2->value];

            // If a JSON-LD context document is configured for this credential,
            // append the module-hosted context URL so that verifiers can
            // resolve the custom credential subject terms.
            if ($this->moduleConfig->getVciCredentialJsonLdContextFor($resolvedCredentialIdentifier) !== null) {
                $atContext[] = $this->routes->urlCredentialJsonLdContext($resolvedCredentialIdentifier);
            }

            // Append any additional context URLs declared in the credential
            // configuration's @context field (skipping the base W3C URL,
            // which is already first in the list).
            /**
             * @psalm-suppress MixedArrayAccess
             * @psalm-suppress MixedAssignment
             */
            $configuredContexts = $resolvedCredentialConfiguration[ClaimsEnum::CredentialDefinition->value]
            [ClaimsEnum::AtContext->value] ?? $resolvedCredentialConfiguration[ClaimsEnum::AtContext->value] ?? [];
            if (is_array($configuredContexts)) {
                /** @psalm-suppress MixedAssignment */
                foreach ($configuredContexts as $configuredContext) {
                    if (
                        is_string($configuredContext) &&
                        $configuredContext !== AtContextsEnum::W3OrgNsCredentialsV2->value &&
                        !in_array($configuredContext, $atContext, true)
                    ) {
                        $atContext[] = $configuredContext;
                    }
                }
            }

            $sdJwtPayload = [
                ClaimsEnum::AtContext->value => $atContext,
                ClaimsEnum::Id->value => $vcId,
                /** @psalm-suppress MixedArrayAccess */
                ClaimsEnum::Type->value => $resolvedCredentialConfiguration[ClaimsEnum::CredentialDefinition->value]
                    [ClaimsEnum::Type->value] ?? [
                        CredentialTypesEnum::VerifiableCredential->value,
                        $resolvedCredentialIdentifier,
                    ],
                    ClaimsEnum::Issuer->value => $issuerDid,
                    ClaimsEnum::ValidFrom->value => $issuedAt->format(\DateTimeInterface::RFC3339),
                    ClaimsEnum::Credential_Subject->value =>
                    $credentialSubject[ClaimsEnum::Credential_Subject->value] ?? [],
                    ClaimsEnum::Iss->value => $issuerDid,
                    ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                    ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                    ClaimsEnum::Sub->value => $sub,
                    ClaimsEnum::Jti->value => $vcId,
            ];

            if ($proof instanceof OpenId4VciProof && is_string($proofKeyId = $proof->getKeyId())) {
                $sdJwtPayload[ClaimsEnum::Cnf->value] = [
                    ClaimsEnum::Kid->value => $proofKeyId,
                ];
            }

            $verifiableCredential = $this->verifiableCredentials->vcSdJwtFactory()->fromData(
                $signingKey,
                $signatureAlgorithm,
                $sdJwtPayload,
                [
                    ClaimsEnum::Kid->value => $issuerDid . '#0',
                ],
                disclosureBag: $disclosureBag,
            );
        }

        if ($verifiableCredential === null) {
            throw new OpenIdException('Invalid credential format ID.');
        }

        if (is_string($issuerState)) {
            $this->loggerService->debug('Revoking issuer state.', ['issuerState' => $issuerState]);
            $this->issuerStateRepository->revoke($issuerState);
        }

        $this->loggerService->debug('Returning credential response.', [
            'credentials' => [
                ['credential' => $verifiableCredential->getToken()],
            ],
        ],);

        return $this->routes->newJsonResponse(
            [
                'credentials' => [
                    ['credential' => $verifiableCredential->getToken()],
                ],
            ],
        );
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

            if (!isset($temp[$key])) {
                $temp[$key] = [];
            }

            $temp = &$temp[$key];
        }

        // If the value is an array and holds only one element, we will set the value directly.
        if (is_array($value) && count($value) === 1) {
            $temp = $value[0];
        } else {
            $temp = $value;
        }
    }
}
