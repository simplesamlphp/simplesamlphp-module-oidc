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
use SimpleSAML\OpenID\Codebooks\CredentialTypesEnum;
use SimpleSAML\OpenID\Codebooks\LanguageTagsEnum;
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

            ClaimsEnum::CredentialConfigurationsSupported->value => [
                'ResearchAndScholarshipCredentialJwtVcJson' => [
                    // REQUIRED
                    ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                    // OPTIONAL
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

                    // OPTIONAL A.1.1.2. https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-vc-signed-as-a-jwt-not-usin
                    ClaimsEnum::Claims->value => [
                        /**
                         * https://refeds.org/category/research-and-scholarship
                         *
                         * The R&S attribute bundle consists (abstractly) of the following required data elements:
                         *
                         * shared user identifier
                         * person name
                         * email address
                         *
                         * and one optional data element:
                         *
                         * affiliation
                         *
                         * where shared user identifier is a persistent, non-reassigned, non-targeted identifier
                         * defined to be either of the following:
                         *
                         * eduPersonPrincipalName (if non-reassigned)
                         * eduPersonPrincipalName + eduPersonTargetedID
                         *
                         * and where person name is defined to be either (or both) of the following:
                         *
                         * displayName
                         * givenName + sn
                         *
                         * and where email address is defined to be the mail attribute,
                         *
                         * and where affiliation is defined to be the eduPersonScopedAffiliation attribute.
                         *
                         * All of the above attributes are defined or referenced in the [eduPerson] specification. The
                         * specific naming and format of these attributes is guided by the protocol in use. For SAML
                         * 2.0 the [SAMLAttr] profile MUST be used. This specification may be extended to reference
                         * other protocol-specific formulations as circumstances warrant.
                         */
                        [
                            // REQUIRED
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'eduPersonPrincipalName',
                            ],
                            // OPTIONAL
                            ClaimsEnum::Mandatory->value => true,
                            // OPTIONAL
                            ClaimsEnum::Display->value => [
                                [
                                    // OPTIONAL
                                    ClaimsEnum::Name->value => 'Principal Name',
                                    // OPTIONAL
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'eduPersonTargetedID',
                            ],
                            ClaimsEnum::Mandatory->value => false,
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Targeted ID',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'displayName',
                            ],
                            ClaimsEnum::Mandatory->value => false,
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Display Name',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'givenName',
                            ],
                            ClaimsEnum::Mandatory->value => false,
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Given Name',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'sn',
                            ],
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Last Name',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'mail',
                            ],
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Email Address',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                        [
                            ClaimsEnum::Path->value => [
                                ClaimsEnum::Credential_Subject->value,
                                'eduPersonScopedAffiliation',
                            ],
                            ClaimsEnum::Display->value => [
                                [
                                    ClaimsEnum::Name->value => 'Scoped Affiliation',
                                    ClaimsEnum::Locale->value => LanguageTagsEnum::EnUs->value,
                                ],
                            ],
                        ],
                    ],

                    // REQUIRED
                    ClaimsEnum::CredentialDefinition->value => [
                        ClaimsEnum::Type->value => [
                            CredentialTypesEnum::VerifiableCredential->value,
                            'ResearchAndScholarshipCredentialJwtVcJson',
                        ],
                    ],
                ],
            ],

        ];

        return $this->routes->newJsonResponse($configuration);
    }
}
