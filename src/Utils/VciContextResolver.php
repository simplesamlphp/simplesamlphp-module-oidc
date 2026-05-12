<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

class VciContextResolver
{
    /**
     * VciContextResolver constructor.
     * @param ModuleConfig $moduleConfig
     * @param Routes $routes
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
    ) {
    }

    /**
     * Resolve the @context array for a given credential configuration.
     *
     * @param string $credentialConfigurationId
     * @param array $credentialConfiguration
     * @return array<string>
     */
    public function resolve(string $credentialConfigurationId, array $credentialConfiguration): array
    {
        // Always start with the VCDM 2.0 base context URL (mandatory).
        $atContext = [AtContextsEnum::W3OrgNsCredentialsV2->value];

        // If a JSON-LD context document is configured for this credential,
        // append the module-hosted context URL so that verifiers can
        // resolve the custom credential subject terms.
        if ($this->moduleConfig->getVciCredentialJsonLdContextFor($credentialConfigurationId) !== null) {
            $atContext[] = $this->routes->urlCredentialJsonLdContext($credentialConfigurationId);
        }

        // Append any additional context URLs declared in the credential
        // configuration's @context field (skipping the base W3C URL,
        // which is already first in the list).
        /**
         * @psalm-suppress MixedArrayAccess
         * @psalm-suppress MixedAssignment
         */
        $configuredContexts = $credentialConfiguration[ClaimsEnum::CredentialDefinition->value]
        [ClaimsEnum::AtContext->value] ?? $credentialConfiguration[ClaimsEnum::AtContext->value] ?? [];

        if (is_array($configuredContexts)) {
            /** @psalm-suppress MixedAssignment */
            foreach ($configuredContexts as $configuredContext) {
                if (
                    is_string($configuredContext) &&
                    $configuredContext !== AtContextsEnum::W3OrgNsCredentialsV2->value &&
                    !in_array($configuredContext, $atContext, true)
                ) {
                    $atContext[] = $configuredContext;
                }
            }
        }

        return $atContext;
    }
}
