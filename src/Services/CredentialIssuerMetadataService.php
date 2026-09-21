<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;

/**
 * The OpenID4VCI Credential Issuer Metadata this deployment publishes.
 *
 * Built here rather than in the well-known endpoint's controller because the same document is published
 * twice: at `.well-known/openid-credential-issuer`, and under the `openid_credential_issuer` Entity Type
 * of the Entity Configuration, which is where a wallet following OpenID Fed DCP (Appendix B of DIIP v5)
 * reads it from - and then reads nothing else. Two builders would be two documents that have to be kept
 * in step; one builder makes them one document by construction. The OP metadata is served to both of
 * its endpoints the same way, by OpMetadataService.
 *
 * Built on the first request for it, unlike OpMetadataService, which builds in its constructor. Reading
 * the Verifiable Credential settings is what building this means, and the Entity Configuration is also
 * published by deployments which have none. The cost is therefore paid by a caller that asks, after it
 * checked that Verifiable Credentials are enabled, and not by every consumer that is merely wired to it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Services\CredentialIssuerMetadataServiceTest
 */
class CredentialIssuerMetadataService
{
    /**
     * @var ?array<string,mixed>
     */
    protected ?array $metadata = null;

    /**
     * Memoised across the credential configurations of one published document.
     *
     * @var ?list<string>
     */
    protected ?array $resolvableDidMethods = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly VciContextResolver $vciContextResolver,
        // The factory rather than the built facade, so that constructing this service reads no
        // configuration. Building the facade validates the DID destination settings and the VCI cache
        // adapter, which only a credential configuration that binds a holder key has any use for.
        protected readonly DidFactory $didFactory,
    ) {
    }


    /**
     * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
     *
     * @return array<string,mixed>
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \Exception
     */
    public function getMetadata(): array
    {
        return $this->metadata ??= $this->buildMetadata();
    }


    /**
     * @return array<string,mixed>
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \Exception
     */
    protected function buildMetadata(): array
    {
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

        $metadata = [
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
            $metadata[ClaimsEnum::BatchCredentialIssuance->value] = [
                ClaimsEnum::BatchSize->value => ModuleConfig::VCI_BATCH_SIZE,
            ];
        }

        return $metadata;
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
