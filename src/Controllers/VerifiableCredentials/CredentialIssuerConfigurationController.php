<?php

declare(strict_types=1);

/*
 *        |
 *   \  ___  /                           _________
 *  _  /   \  _    GÉANT                 |  * *  | Co-Funded by
 *     | ~ |       Trust & Identity      | *   * | the European
 *      \_/        Incubator             |__*_*__| Union
 *       =
 */

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerConfigurationController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }

    public function configuration(): Response
    {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p

        $signer = $this->moduleConfig->getProtocolSigner();

        $credentialConfigurationsSupported = $this->moduleConfig->getCredentialConfigurationsSupported();

        // For now, we only support one credential signing algorithm.
        /** @psalm-suppress MixedAssignment */
        foreach ($credentialConfigurationsSupported as $credentialConfigurationId => $credentialConfiguration) {
            if (is_array($credentialConfiguration)) {
                // Draft 17
                $credentialConfiguration[ClaimsEnum::CredentialSigningAlgValuesSupported->value] = [
                    $signer->algorithmId(),
                ];
                // Earlier drafts
                // TODO mivanci Delete CryptographicSuitesSupported once we are on the final draft.
                $credentialConfiguration[ClaimsEnum::CryptographicSuitesSupported->value] = [
                    $signer->algorithmId(),
                ];
                $credentialConfigurationsSupported[$credentialConfigurationId] = $credentialConfiguration;
            }
        }

        $configuration = [
            ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),

            // OPTIONAL // WND
            // authorization_servers

            // REQUIRED
            ClaimsEnum::CredentialEndpoint->value => $this->routes->urlCredentialIssuerCredential(),

            // OPTIONAL
            // nonce_endpoint

            // OPTIONAL
            // deferred_credential_endpoint

            // OPTIONAL
            // notification_endpoint

            // OPTIONAL
            // credential_response_encryption

            // OPTIONAL
            // batch_credential_issuance

            // OPTIONAL
            // signed_metadata

            // OPTIONAL
            ClaimsEnum::Display->value => [
                [
                    ClaimsEnum::Name->value => $this->moduleConfig->getOrganizationName(),
                    ClaimsEnum::Locale->value => 'en-US',
                    // OPTIONAL
                    // logo
                ],

            ],

            ClaimsEnum::CredentialConfigurationsSupported->value => $credentialConfigurationsSupported,

        ];

        return $this->routes->newJsonResponse($configuration);
    }
}
