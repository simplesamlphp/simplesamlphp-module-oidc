<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use League\OAuth2\Server\ResourceServer;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
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
    ) {
        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled');
        }
    }

    public function credential(Request $request): Response
    {
        $this->loggerService->info('credential', $request->request->all());


        $authorization = $this->resourceServer->validateAuthenticatedRequest(
            $this->psrHttpBridge->getPsrHttpFactory()->createRequest($request),
        );

        // TODO mivanci validate
        $accessToken = $this->accessTokenRepository->findById($authorization->getAttribute('oauth_access_token_id'));
        if ($accessToken->isRevoked()) {
            throw OidcServerException::accessDenied('Access token is revoked.');
        }

        // TODO mivanci validate requested credential identifier

        $jwk = $this->jwk->jwkDecoratorFactory()->fromPkcs1Or8KeyFile(
            $this->moduleConfig->getProtocolPrivateKeyPath(),
            null,
        );

        $issuedAt = new \DateTimeImmutable();

        $verifiableCredential = $this->verifiableCredentials->jwtVcJsonFactory()->fromData(
            $jwk,
            SignatureAlgorithmEnum::RS256,
            [
                ClaimsEnum::Vc->value => [
                    ClaimsEnum::AtContext->value => [
                        AtContextsEnum::W3Org2018CredentialsV1->value,
                    ],
                    ClaimsEnum::Type->value => [
                        CredentialTypesEnum::VerifiableCredential->value,
                        'ResearchAndScholarshipCredentialJwtVcJson',
                    ],
                    ClaimsEnum::Issuer->value => $this->moduleConfig->getIssuer(),
                    ClaimsEnum::Issuance_Date->value => $issuedAt->format(\DateTimeInterface::RFC3339),
                    ClaimsEnum::Credential_Subject->value => [
                        'eduPersonPrincipalName' => 'testuser@example.com',
                        'eduPersonTargetedID' => 'abc123',
                        'displayName' => 'Test User',
                        'givenName' => 'Test',
                        'sn' => 'User',
                        'mail' => 'testuser@example.com',
                        'eduPersonScopedAffiliation' => 'member@example.com',
                    ],
                ],
                ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
                ClaimsEnum::Iat->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Nbf->value => $issuedAt->getTimestamp(),
                ClaimsEnum::Sub->value => 'testuid',
            ],
            [
                ClaimsEnum::Kid->value => FingerprintGenerator::forFile(
                    $this->moduleConfig->getProtocolCertPath(),
                ),
            ],
        );

        $this->loggerService->debug('response', [
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
}
