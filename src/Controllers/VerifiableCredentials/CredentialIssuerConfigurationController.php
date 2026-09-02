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

use SimpleSAML\Module\oidc\Factories\DidFactory;
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
     * Memoised across the credential configurations of one published document.
     *
     * @var ?list<string>
     */
    protected ?array $resolvableDidMethods = null;


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
        protected readonly VciContextResolver $vciContextResolver,
        // The factory rather than the built facade. Constructing one reads no configuration, whereas
        // building the facade validates the DID destination settings and the VCI cache adapter - and
        // the container resolves every constructor argument before the guard below runs, so taking a
        // built one would answer a request this endpoint refuses outright, or one for a deployment
        // binding nothing at all, by failing on DID settings neither has any use for.
        protected readonly DidFactory $didFactory,
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

                // Asked of the policy against the resolver registry rather than written out here, so
                // that what this advertises and what the Credential Endpoint accepts are one answer
                // instead of two lists which have to be kept in step. A DID method the library gains is
                // advertised by every configuration whose policy accepts it without this line changing,
                // and a policy added later has to say what it binds rather than falling into whichever
                // branch an `if` here happened to leave open.
                //
                // Only a configuration which binds needs the registry, and only then is it worth
                // building the DID facade to ask for it: a deployment issuing nothing but proofless
                // credentials publishes this document without its DID settings ever being read.
                $bindingMethods = $bindingPolicy->requiresKeyProof() ?
                $bindingPolicy->bindingMethodsFrom($this->resolvableDidMethods()) :
                null;

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


    /**
     * The DID methods this deployment can resolve, which is what every binding advertisement is
     * filtered from.
     *
     * Built once for the whole document rather than per credential configuration, since the registry
     * is the same for all of them and building the facade is what reads the DID settings.
     *
     * @return list<string>
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \Exception
     */
    protected function resolvableDidMethods(): array
    {
        return $this->resolvableDidMethods ??= $this->didFactory->build()->supportedMethods();
    }
}
