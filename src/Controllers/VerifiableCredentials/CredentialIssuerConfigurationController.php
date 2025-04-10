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
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerConfigurationController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
    ) {
        if (!$this->moduleConfig->getVerifiableCredentialEnabled()) {
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled');
        }
    }

    public function configuration(): Response
    {
        // TODO mivanci Abstract configuring Credential Issuer / Configuration away from module config.
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p

        $signer = $this->moduleConfig->getProtocolSigner();

        $configuration = [
            ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),

            // OPTIONAL // WND
            // authorization_servers

            // REQUIRED
            // TODO credential_endpoint

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

            ClaimsEnum::CredentialConfigurationsSupported->value => [
                'ResearchAndScholarshipCredentialJwtVcJson' => [
                    ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                    ClaimsEnum::Scope->value => 'ResearchAndScholarshipCredentialJwtVcJson',

                    // OPTIONAL
                    // cryptographic_binding_methods_supported

                    // OPTIONAL
                    ClaimsEnum::CredentialSigningAlgValuesSupported->value => [
                        $signer->algorithmId(),
                    ],

                    // OPTIONAL
                    // proof_types_supported

                    ClaimsEnum::Display->value => [
                        [
                            ClaimsEnum::Name->value => 'ResearchAndScholarshipCredentialJwtVcJson',
                            ClaimsEnum::Locale->value => 'en-US',

                            // OPTIONAL
                            // logo

                            // OPTIONAL
                            ClaimsEnum::Description->value => 'Research and Scholarship Credential',

                            // OPTIONAL
                            // background_color

                            // OPTIONAL
                            // background_image

                            // OPTIONAL
                            // text_color
                        ],
                    ],

                    // As per appendix A.1.1.2. https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-signed-as-a-jwt-not-usin
                    ClaimsEnum::Claims->value => [
                        [

                        ],
                    ],
                ],
            ],

        ];

        return $this->routes->newJsonResponse($configuration);
    }
}
