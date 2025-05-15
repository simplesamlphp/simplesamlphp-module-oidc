<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use Base64Url\Base64Url;
use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
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
    ) {
        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled');
        }
    }

    public function credential(Request $request): Response
    {
        $this->loggerService->info('Request data: ',
        $this->requestParamsResolver->getAllFromRequest(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
        ));


        $authorization = $this->resourceServer->validateAuthenticatedRequest(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
        );

        // TODO mivanci validate
        $accessToken = $this->accessTokenRepository->findById($authorization->getAttribute('oauth_access_token_id'));
        if ($accessToken->isRevoked()) {
            throw OidcServerException::accessDenied('Access token is revoked.');
        }

        // TODO mivanci validate requested credential identifier

        $signingKey = $this->jwk->jwkDecoratorFactory()->fromPkcs1Or8KeyFile(
            $this->moduleConfig->getProtocolPrivateKeyPath(),
            null,
        );

        $publicKey = $this->jwk->jwkDecoratorFactory()->fromPkcs1Or8KeyFile(
            $this->moduleConfig->getProtocolCertPath(),
            null,
            [
                //ClaimsEnum::Use->value => 'sig',
            ]
        );

        $base64PublicKey = json_encode($publicKey->jwk()->all(), JSON_UNESCAPED_SLASHES);
        $base64PublicKey = Base64Url::encode($base64PublicKey);

        $issuerDid = 'did:jwk:' . $base64PublicKey;


        $issuedAt = new \DateTimeImmutable();

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
                        'ResearchAndScholarshipCredentialJwtVcJson',
                    ],
//                    ClaimsEnum::Issuer->value => $this->moduleConfig->getIssuer(),
//                    ClaimsEnum::Issuer->value => $issuerDid,
                    ClaimsEnum::Issuer->value => 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/jwks',
                    ClaimsEnum::Issuance_Date->value => $issuedAt->format(\DateTimeInterface::RFC3339),
                    ClaimsEnum::Id->value => $this->moduleConfig->getIssuer() . '/vc/1234567890',
                    ClaimsEnum::Credential_Subject->value => [
                        ClaimsEnum::Id->value => $this->moduleConfig->getIssuer() . '/sub/1234567890',
                        'eduPersonPrincipalName' => 'testuser@example.com',
                        'eduPersonTargetedID' => 'abc123',
                        'displayName' => 'Test User',
                        'givenName' => 'Test',
                        'sn' => 'User',
                        'mail' => 'testuser@example.com',
                        'eduPersonScopedAffiliation' => 'member@example.com',
                    ],
                ],
//                ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
//                ClaimsEnum::Iss->value => $issuerDid,
                ClaimsEnum::Iss->value => 'https://idp.mivanci.incubator.hexaa.eu/ssp/module.php/oidc/jwks',
                ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Sub->value => $this->moduleConfig->getIssuer() . '/sub/1234567890',
                ClaimsEnum::Jti->value => $this->moduleConfig->getIssuer() . '/vc/1234567890',
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
}
