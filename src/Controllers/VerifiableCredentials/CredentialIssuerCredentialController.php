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
use SimpleSAML\Module\oidc\Utils\DidKeyResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\VerifiableCredentials;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerCredentialController
{
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
        protected readonly DidKeyResolver $didKeyResolver,
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

        // Validate credential request, including proof
        if (isset($requestData['proof']) && isset($requestData['proof']['proof_type']) && 
            $requestData['proof']['proof_type'] === 'jwt' && isset($requestData['proof']['jwt'])) {

            $proofJwt = $requestData['proof']['jwt'];
            $this->loggerService->debug('Verifying proof JWT: ' . $proofJwt);

            try {
                // Parse the JWT to extract header and payload
                $jwtParts = explode('.', $proofJwt);
                if (count($jwtParts) !== 3) {
                    throw OidcServerException::invalidRequest('Invalid JWT format in proof');
                }

                $header = json_decode(Base64Url::decode($jwtParts[0]), true);
                $payload = json_decode(Base64Url::decode($jwtParts[1]), true);

                if (!isset($payload['iss'])) {
                    throw OidcServerException::invalidRequest('Missing issuer (iss) in proof JWT');
                }

                $issuer = $payload['iss'];
                $this->loggerService->debug('Proof JWT issuer: ' . $issuer);

                // Check if the issuer is a did:key
                if (str_starts_with($issuer, 'did:key:')) {
                    $this->loggerService->debug('Extracting JWK from did:key: ' . $issuer);

                    // Extract JWK from did:key
                    $jwk = $this->didKeyResolver->extractJwkFromDidKey($issuer);

                    // If kid is present in the header, add it to the JWK
                    if (isset($header['kid'])) {
                        $jwk['kid'] = $header['kid'];
                    } else {
                        // If no kid in header, use the did:key as kid
                        $jwk['kid'] = $issuer;
                    }

                    $this->loggerService->debug('Extracted JWK: ', $jwk);

                    // TODO: Verify the JWT signature using the extracted JWK
                    // This would typically involve using a JWT library to verify the signature
                    // For now, we'll just log that we've extracted the JWK successfully
                    $this->loggerService->debug('JWK extracted successfully from did:key');
                }
            } catch (\Exception $e) {
                $this->loggerService->error('Error processing proof JWT: ' . $e->getMessage());
                throw OidcServerException::invalidRequest('Error processing proof JWT: ' . $e->getMessage());
            }
        }

        /**
         * Sample proof structure:
         * 'proof' =>
         * array (
         * 'proof_type' => 'jwt',
         * 'jwt' => 'eyJ0eXAiOiJvcGVuaWQ0dmNpLXByb29mK2p3dCIsImFsZyI6IkVTMjU2Iiwia2lkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JyU2ZYMkJVeHNVaW5QbVA3QUVzZEN4OWpQYlV0ZkIzWXN2MTd4TGpyZkMxeDNVZmlMTWtyeWdTZDJMeWltQ3RGejhHWlBqOFFrMUJFU0F6M21LWGRCTEpuUHNNQ0R4Nm9QNjNuZVpmR1NKelF5SjRLVlN6Nmt4UTJQOTE4NGdXS1FnI3oyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnJTZlgyQlV4c1VpblBtUDdBRXNkQ3g5alBiVXRmQjNZc3YxN3hManJmQzF4M1VmaUxNa3J5Z1NkMkx5aW1DdEZ6OEdaUGo4UWsxQkVTQXozbUtYZEJMSm5Qc01DRHg2b1A2M25lWmZHU0p6UXlKNEtWU3o2a3hRMlA5MTg0Z1dLUWcifQ.eyJhdWQiOiJodHRwczovL2lkcC5taXZhbmNpLmluY3ViYXRvci5oZXhhYS5ldSIsImlhdCI6MTc0ODUxNDE0NywiZXhwIjoxNzQ4NTE0ODA3LCJpc3MiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnJTZlgyQlV4c1VpblBtUDdBRXNkQ3g5alBiVXRmQjNZc3YxN3hManJmQzF4M1VmaUxNa3J5Z1NkMkx5aW1DdEZ6OEdaUGo4UWsxQkVTQXozbUtYZEJMSm5Qc01DRHg2b1A2M25lWmZHU0p6UXlKNEtWU3o2a3hRMlA5MTg0Z1dLUWciLCJqdGkiOiJiMmNlZDQ2Yi0zOWNiLTRkZDAtYmQxZS1hNzY5ZWNlOWUxMTIifQ.SPdMSnrfF8ybhfYluzz5OrfWJQDOpCu7-of8zVbp5UR89GaB7j14Egext1h9pYgl6JwIP8zibUjTSc8JLVYuvA',
         * ),
         */

        // TODO mivanci Check / handle credential_identifier parameter.

        $credentialConfigurationId = $requestData[ClaimsEnum::CredentialConfigurationId->value] ?? null;

        if (is_null($credentialConfigurationId)) {
            // Check per draft 14
            if (is_array(
                $credentialDefinitionType =
                    $requestData[ClaimsEnum::CredentialDefinition->value][ClaimsEnum::Type->value],
            )
            ) {
                $credentialConfigurationId =
                    $this->moduleConfig->getCredentialConfigurationIdForCredentialDefinitionType(
                        $credentialDefinitionType,
                    );
            }
        }

        if (is_null($credentialConfigurationId)) {
            return $this->routes->newJsonErrorResponse(
                'invalid_credential_request',
                'Can not resolve credential configuration ID.',
            );
        }

        if (!in_array($credentialConfigurationId, $this->moduleConfig->getCredentialConfigurationIdsSupported())) {
            return $this->routes->newJsonErrorResponse(
                'unsupported_credential_type',
                sprintf('Credential configuration ID "%s" is not supported.', $credentialConfigurationId),
            );
        }

        $userId = $accessToken->getUserIdentifier();
        $userEntity = $this->userRepository->getUserEntityByIdentifier($userId);
        if ($userEntity === null) {
            throw OidcServerException::invalidRequest('User not found');
        }

        $userAttributes = $userEntity->getClaims();

        // Get valid claim paths so we can check if the user attribute is allowed to be included in the credential,
        // as per the credential configuration supported configuration.
        $validClaimPaths = $this->moduleConfig->getValidCredentialClaimPathsFor($credentialConfigurationId);

        // Map user attributes to credential claims
        $credentialSubject = [];
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
            if (isset($userAttributes[$userAttributeName])) {
                $this->setCredentialClaimValue(
                    $credentialSubject,
                    $credentialClaimPath,
                    $userAttributes[$userAttributeName],
                );
            }
        }

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

        $verifiableCredential = $this->verifiableCredentials->jwtVcJsonFactory()->fromData(
            $signingKey,
            SignatureAlgorithmEnum::from($this->moduleConfig->getProtocolSigner()->algorithmId()),
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
            //ClaimsEnum::Issuer->value => 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/jwks',
                    ClaimsEnum::Issuance_Date->value => $issuedAt->format(\DateTimeInterface::RFC3339),
                    ClaimsEnum::Id->value => $vcId,
                    ClaimsEnum::Credential_Subject->value =>
                        $credentialSubject[ClaimsEnum::Credential_Subject->value] ?? [],
                ],
                //ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::Iss->value => $issuerDid,
            //ClaimsEnum::Iss->value => 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/jwks',
                ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Sub->value => $this->moduleConfig->getIssuer() . '/sub/' . $userId,
                ClaimsEnum::Jti->value => $vcId,
            ],
            [
                ClaimsEnum::Kid->value => $issuerDid . '#0',
            ],
        );

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
