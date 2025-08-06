<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use Base64Url\Base64Url;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Exceptions\OpenId4VciProofException;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerCredentialController
{
    public const SD_JWT_FORMAT_IDS = [
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
        protected readonly Jwk $jwk,
        protected readonly LoggerService $loggerService,
        protected readonly RequestParamsResolver $requestParamsResolver,
        protected readonly UserRepository $userRepository,
        protected readonly Did $did,
    ) {
        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled');
        }
    }

    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \ReflectionException
     */
    public function credential(Request $request): Response
    {
        $requestData = $this->requestParamsResolver->getAllFromRequestBasedOnAllowedMethods(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
            [HttpMethodsEnum::POST],
        );

        $this->loggerService->debug('Verifiable Credential request data: ', $requestData);

        $authorization = $this->resourceServer->validateAuthenticatedRequest(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
        );

        // TODO mivanci validate access token
        $accessToken = $this->accessTokenRepository->findById($authorization->getAttribute('oauth_access_token_id'));
        if ($accessToken->isRevoked()) {
            return $this->routes->newJsonErrorResponse(
                'invalid_token',
                'Access token is revoked.',
                401,
            );
        }

        // TODO mivanci Validate credential request

        $credentialFormatId = $requestData[ClaimsEnum::Format->value] ?? null;

        if (is_null($credentialFormatId)) {
            throw OidcServerException::serverError('Credential format missing in request.');
        }

        if (
            !in_array($credentialFormatId, [
                CredentialFormatIdentifiersEnum::JwtVcJson->value,
                CredentialFormatIdentifiersEnum::DcSdJwt->value,
                CredentialFormatIdentifiersEnum::VcSdJwt->value, // Deprecated value, but let's support it for now.
            ])
        ) {
            return $this->routes->newJsonErrorResponse(
                'unsupported_credential_type',
                sprintf('Credential format ID "%s" is not supported.', $credentialFormatId),
            );
        }

        // TODO mivanci Check / handle credential_identifier parameter.

        $credentialConfigurationId = $requestData[ClaimsEnum::CredentialConfigurationId->value] ?? null;

        if (is_null($credentialConfigurationId)) {
            // TODO mivanci Update this to newest draft.
            // Check per draft 14 (Sphereon wallet case).
            if (
                $credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value &&
                is_array(
                    $credentialDefinitionType =
                    $requestData[ClaimsEnum::CredentialDefinition->value][ClaimsEnum::Type->value] ?? null,
                )
            ) {
                $credentialConfigurationId =
                $this->moduleConfig->getCredentialConfigurationIdForCredentialDefinitionType(
                    $credentialDefinitionType,
                );
            } elseif (
                in_array($credentialFormatId, self::SD_JWT_FORMAT_IDS, true) &&
                is_string($vct = $requestData[ClaimsEnum::Vct->value] ?? null)
            ) {
                $credentialConfigurationId = $vct;
            }
        }

        if (is_null($credentialConfigurationId)) {
            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Can not resolve credential configuration ID.',
            );
        }

        if (!is_array($this->moduleConfig->getCredentialConfiguration($credentialConfigurationId))) {
            return $this->routes->newJsonErrorResponse(
                'unsupported_credential_type',
                sprintf('Credential configuration ID "%s" is not supported.', $credentialConfigurationId),
            );
        }

        $userId = $accessToken->getUserIdentifier();
        $userEntity = $this->userRepository->getUserEntityByIdentifier($userId);
        if ($userEntity === null) {
            throw OidcServerException::invalidRequest('User not found.');
        }

        // Placeholder sub identifier. Will do if proof is not provided.
        $sub = $this->moduleConfig->getIssuer() . '/sub/' . $userId;

        $proof = null;
        // Validate proof, if provided.
        // TODO mivanci consider making proof mandatory (in issuer metadata).
        if (
            isset($requestData['proof']['proof_type']) &&
            isset($requestData['proof']['jwt']) &&
            $requestData['proof']['proof_type'] === 'jwt'
        ) {
            $proofJwt = $requestData['proof']['jwt'];
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

                $kid = $proof->getKeyId();
                if (is_string($kid) && str_starts_with($kid, 'did:key:z')) {
                    // The fragment (#z2dmzD...) typically points to a specific verification method within the DID's
                    // context. For did:key, since the DID is the key, this fragment often just refers to the key
                    // itself.
                    ($didKey = strtok($kid, '#')) || throw new OpenId4VciProofException(
                        'Error getting did:key without fragment. Value was: ' . $kid,
                    );

                    $jwk = $this->did->didKeyResolver()->extractJwkFromDidKey($didKey);

                    $proof->verifyWithKey($jwk);

                    $this->loggerService->debug('Proof verified successfully using did:key ' . $didKey);
                    // Set it as a subject identifier (bind it).
                    $sub = $didKey;
                } else {
                    $this->loggerService->warning(
                        'Proof currently not supported. ',
                        ['header' => $proof->getHeader(), 'payload' => $proof->getPayload()],
                    );
                }
            } catch (\Exception $e) {
                $message = 'Error processing proof JWT: ' . $e->getMessage();
                $this->loggerService->error($message);
                return $this->routes->newJsonErrorResponse(
                    'invalid_proof',
                    $message,
                );
            }
        }

        $userAttributes = $userEntity->getClaims();

        // Get valid claim paths so we can check if the user attribute is allowed to be included in the credential,
        // as per the credential configuration supported configuration.
        $validClaimPaths = $this->moduleConfig->getValidCredentialClaimPathsFor($credentialConfigurationId);

        // Map user attributes to credential claims
        $credentialSubject = []; // For JwtVcJson
        $disclosureBag = $this->verifiableCredentials->disclosureBagFactory()->build(); // For DcSdJwt
        $attributeToCredentialClaimPathMap = $this->moduleConfig->getUserAttributeToCredentialClaimPathMapFor(
            $credentialConfigurationId,
        );
        foreach ($attributeToCredentialClaimPathMap as $mapEntry) {
            $userAttributeName = key($mapEntry);
            $credentialClaimPath = current($mapEntry);
            if (!in_array($credentialClaimPath, $validClaimPaths)) {
                $this->loggerService->warning(
                    'Attribute "%s" does not use one of valid credential claim paths.',
                    $mapEntry,
                );
                continue;
            }

            if (!isset($userAttributes[$userAttributeName])) {
                $this->loggerService->warning(
                    'Attribute "%s" does not exist in user attributes.',
                    $mapEntry,
                );
                continue;
            }

            if ($credentialFormatId === CredentialFormatIdentifiersEnum::JwtVcJson->value) {
                $this->setCredentialClaimValue(
                    $credentialSubject,
                    $credentialClaimPath,
                    $userAttributes[$userAttributeName],
                );
            }

            if (in_array($credentialFormatId, self::SD_JWT_FORMAT_IDS, true)) {
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

                $disclosure = $this->verifiableCredentials->disclosureFactory()->build(
                    value: $userAttributes[$userAttributeName],
                    name: $claimName,
                    path: is_array($credentialClaimPath) ? $credentialClaimPath : [],
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

        $signingKey = $this->jwk->jwkDecoratorFactory()->fromPkcs1Or8KeyFile(
            $this->moduleConfig->getProtocolPrivateKeyPath(),
            null,
        );

        $publicKey = $this->jwk->jwkDecoratorFactory()->fromPkcs1Or8KeyFile(
            $this->moduleConfig->getProtocolCertPath(),
            null,
            [
                //ClaimsEnum::Use->value => 'sig',
            ],
        );

        $base64PublicKey = json_encode($publicKey->jwk()->all(), JSON_UNESCAPED_SLASHES);
        $base64PublicKey = Base64Url::encode($base64PublicKey);

        $issuerDid = 'did:jwk:' . $base64PublicKey;

        $issuedAt = new \DateTimeImmutable();

        $vcId = $this->moduleConfig->getIssuer() . '/vc/' . uniqid();
        $signatureAlgorithm = SignatureAlgorithmEnum::from($this->moduleConfig->getProtocolSigner()->algorithmId());

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
                        ClaimsEnum::Type->value => [
                            CredentialTypesEnum::VerifiableCredential->value,
                            $credentialConfigurationId,
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

        if (in_array($credentialFormatId, self::SD_JWT_FORMAT_IDS, true)) {
            $sdJwtPayload = [
                ClaimsEnum::Iss->value => $issuerDid,
                ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Sub->value => $sub,
                ClaimsEnum::Jti->value => $vcId,
                ClaimsEnum::Vct->value => $credentialConfigurationId,
            ];

            if ($proof instanceof OpenId4VciProof) {
                $sdJwtPayload[ClaimsEnum::Cnf->value] = [
                    ClaimsEnum::Kid->value => $proof->getKeyId(),
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
                jwtTypesEnum: JwtTypesEnum::VcSdJwt,
            );
        }

        $this->loggerService->debug('response', [
            'credentials' => [
                ['credential' => $verifiableCredential->getToken()],
            ],
        ],);

        return $this->routes->newJsonResponse(
            ['credential' => $verifiableCredential->getToken()],
            //            [
            //                'credentials' => [
            //                    ['credential' => $verifiableCredential->getToken()],
            //                ]
            //            ],
        );
    }

    /**
     * Helper method to set a claim value at a path. Supports creating nested arrays dynamically.
     */
    protected function setCredentialClaimValue(array &$claims, array $path, mixed $value): void
    {
        $temp = &$claims;

        foreach ($path as $key) {
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
