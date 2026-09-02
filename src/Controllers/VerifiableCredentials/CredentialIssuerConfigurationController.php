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

use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
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
        protected readonly LoggerService $loggerService,
        protected readonly VciContextResolver $vciContextResolver,
    ) {
        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    public function configuration(): Response
    {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p

        $signatureKeyPair = $this->moduleConfig->getActiveVciSignatureKeyPair();

        $credentialConfigurationsSupported = $this->moduleConfig->getVciCredentialConfigurationsSupported();

        $isAnyConfigurationProofBound = false;

        // Every credential configuration advertises the one algorithm the active signing key uses,
        // because that is the only one issuance will actually sign with. Advertising the algorithms of
        // the other configured pairs would invite a wallet to ask for a credential this issuer would
        // then sign with something else.
        /** @psalm-suppress MixedAssignment */
        foreach ($credentialConfigurationsSupported as $credentialConfigurationId => $credentialConfiguration) {
            $credentialConfigurationId = (string) $credentialConfigurationId;
            if (is_array($credentialConfiguration)) {
                $credentialConfiguration[ClaimsEnum::CredentialSigningAlgValuesSupported->value] = [
                    $signatureKeyPair->getSignatureAlgorithm()->value,
                ];

                $bindingPolicy = $this->moduleConfig->getVciCredentialBindingPolicyFor($credentialConfigurationId);

                // A match rather than a comparison, so that a binding policy added later has to state
                // what it advertises here instead of falling into whichever branch was written as the
                // alternative - which for this pair would have silently unadvertised binding for it.
                $bindingMethods = match ($bindingPolicy) {
                    // `jwk` is not a DID method: OpenID4VCI defines it as the value for a credential
                    // bound to a key in JWK format, which is what a key proof carrying its key inline
                    // in a `jwk` header produces. This configuration accepts those and states the key
                    // in `cnf.jwk`, so leaving the value out would hide a supported path from every
                    // wallet which reads this metadata to decide what to send.
                    VciCredentialBindingPolicyEnum::ProofBound => ['did:key', 'did:jwk', 'did:web', 'jwk'],
                    // The profile names these two, and its rules confine a holder to them: the proof's
                    // key has to sit under the DID its `iss` claim states.
                    VciCredentialBindingPolicyEnum::DiipProofBound => ['did:jwk', 'did:web'],
                    VciCredentialBindingPolicyEnum::Proofless => null,
                };

                if ($bindingMethods !== null) {
                    $isAnyConfigurationProofBound = true;

                    $credentialConfiguration[ClaimsEnum::CryptographicBindingMethodsSupported->value] =
                    $bindingMethods;
                    $credentialConfiguration[ClaimsEnum::ProofTypesSupported->value] = [
                        OpenId4VciProofValidator::PROOF_TYPE_JWT => [
                            ClaimsEnum::ProofSigningAlgValuesSupported->value => $this->moduleConfig
                                ->getSupportedAlgorithms()
                                ->getSignatureAlgorithmBag()
                                ->getAllNamesUnique(),
                        ],
                    ];
                } else {
                    // Both fields go, not just one. OpenID4VCI requires `proof_types_supported` wherever
                    // `cryptographic_binding_methods_supported` appears, and requires a `proofs`
                    // parameter wherever `proof_types_supported` appears, so leaving either in place
                    // would promise a wallet a binding this configuration does not perform. Unset rather
                    // than skipped, because the credential configurations are published as the operator
                    // wrote them and may state either field themselves.
                    unset(
                        $credentialConfiguration[ClaimsEnum::CryptographicBindingMethodsSupported->value],
                        $credentialConfiguration[ClaimsEnum::ProofTypesSupported->value],
                    );
                }

                $credentialFormatId = $credentialConfiguration[ClaimsEnum::Format->value] ?? null;

                if ($credentialFormatId === CredentialFormatIdentifiersEnum::VcSdJwt->value) {
                    $atContext = $this->vciContextResolver->resolve(
                        $credentialConfigurationId,
                        $credentialConfiguration,
                    );

                    /** @psalm-suppress MixedArrayAccess */
                    if (isset($credentialConfiguration[ClaimsEnum::CredentialDefinition->value])) {
                        /** @psalm-suppress MixedArrayAssignment */
                        $credentialConfiguration[ClaimsEnum::CredentialDefinition->value][ClaimsEnum::AtContext->value]
                        = $atContext;
                    } else {
                        $credentialConfiguration[ClaimsEnum::AtContext->value] = $atContext;
                    }
                }

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
            ClaimsEnum::NonceEndpoint->value => $this->routes->urlCredentialIssuerNonce(),

            // OPTIONAL
            // deferred_credential_endpoint

            // OPTIONAL
            // notification_endpoint

            // OPTIONAL
            // credential_response_encryption

            // OPTIONAL
            // signed_metadata

            // OPTIONAL
            ClaimsEnum::Display->value => [
                [
                    ClaimsEnum::Name->value => $this->moduleConfig->getOrganizationName(),
                    ClaimsEnum::Locale->value => 'en-US',
                    ClaimsEnum::Description->value => $this->moduleConfig->getDescription() ?? 'SimpleSAMLphp Demo VCI',
                    ClaimsEnum::Logo->value => [
                        ClaimsEnum::Uri->value => $this->moduleConfig->getLogoUri(),
                        ClaimsEnum::AltText->value => ($this->moduleConfig->getOrganizationName() ?? 'VCI') . ' logo',
                    ],
                ],

            ],

            ClaimsEnum::CredentialConfigurationsSupported->value => $credentialConfigurationsSupported,

        ];

        // The cap the credential endpoint enforces on a `proofs` array, stated where a wallet can read
        // it before it builds one. Batching only happens where key proofs do, so an issuer whose every
        // configuration issues unbound credentials advertises no batch size at all.
        if ($isAnyConfigurationProofBound) {
            $configuration[ClaimsEnum::BatchCredentialIssuance->value] = [
                ClaimsEnum::BatchSize->value => ModuleConfig::VCI_BATCH_SIZE,
            ];
        }

        return $this->routes->newJsonResponse($configuration);
    }
}
