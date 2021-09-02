<?php

namespace SimpleSAML\Module\oidc\Services;

/**
 * OpenID Provider Metadata Service - provides information about OIDC authentication server.
 *
 * Class OidcOpenIdProviderMetadataService
 * @package SimpleSAML\Module\oidc\Services
 */
class OidcOpenIdProviderMetadataService
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var array $metadata
     */
    private $metadata;

    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
        $this->initMetadata();
    }

    /**
     * Initialize metadata array.
     */
    public function initMetadata(): void
    {
        $this->metadata = [];
        $this->metadata['issuer'] = $this->configurationService->getSimpleSAMLSelfURLHost();
        $this->metadata['authorization_endpoint'] =
            $this->configurationService->getOpenIdConnectModuleURL('authorize.php');
        $this->metadata['token_endpoint'] = $this->configurationService->getOpenIdConnectModuleURL('access_token.php');
        $this->metadata['userinfo_endpoint'] = $this->configurationService->getOpenIdConnectModuleURL('userinfo.php');
        $this->metadata['jwks_uri'] = $this->configurationService->getOpenIdConnectModuleURL('jwks.php');
        $this->metadata['scopes_supported'] = array_keys($this->configurationService->getOpenIDScopes());
        $this->metadata['response_types_supported'] = ['code', 'token', 'id_token', 'id_token token'];
        $this->metadata['subject_types_supported'] = ['public'];
        $this->metadata['id_token_signing_alg_values_supported'] = ['RS256'];
        $this->metadata['code_challenge_methods_supported'] = ['plain', 'S256'];
        $this->metadata['token_endpoint_auth_methods_supported'] = ['client_secret_post', 'client_secret_basic'];
        $this->metadata['request_parameter_supported'] = false;
        $this->metadata['grant_types_supported'] = ['authorization_code', 'refresh_token'];
        $this->metadata['claims_parameter_supported'] = true;
    }

    /**
     * Get OIDC Provider (OP) metadata array.
     *
     * @return array
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }
}
