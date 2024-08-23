<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * OpenID Provider Metadata Service - provides information about OIDC authentication server.
 *
 * Class OpMetadataService
 * @package SimpleSAML\Module\oidc\Services
 */
class OpMetadataService
{
    private array $metadata;

    /**
     * @throws \Exception
     */
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
        $this->initMetadata();
    }

    /**
     * Initialize metadata array.
     * @throws \Exception
     */
    private function initMetadata(): void
    {
        $this->metadata = [];
        // TODO mivanci Replace keys with enum values.
        $this->metadata['issuer'] = $this->moduleConfig->getIssuer();
        $this->metadata[ClaimsEnum::AuthorizationEndpoint->value] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdAuthorization->value);
        $this->metadata['token_endpoint'] = $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdToken->value);
        $this->metadata['userinfo_endpoint'] = $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdUserInfo->value);
        $this->metadata['end_session_endpoint'] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdEndSession->value);
        $this->metadata['jwks_uri'] = $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdJwks->value);
        $this->metadata['scopes_supported'] = array_keys($this->moduleConfig->getOpenIDScopes());
        $this->metadata['response_types_supported'] = ['code', 'token', 'id_token', 'id_token token'];
        $this->metadata['subject_types_supported'] = ['public'];
        $this->metadata['id_token_signing_alg_values_supported'] = [
            $this->moduleConfig->getProtocolSigner()->algorithmId(),
        ];
        $this->metadata['code_challenge_methods_supported'] = ['plain', 'S256'];
        $this->metadata['token_endpoint_auth_methods_supported'] = ['client_secret_post', 'client_secret_basic'];
        $this->metadata['request_parameter_supported'] = false;
        $this->metadata['grant_types_supported'] = ['authorization_code', 'refresh_token'];
        $this->metadata['claims_parameter_supported'] = true;
        if (!(empty($acrValuesSupported = $this->moduleConfig->getAcrValuesSupported()))) {
            $this->metadata['acr_values_supported'] = $acrValuesSupported;
        }
        $this->metadata['backchannel_logout_supported'] = true;
        $this->metadata['backchannel_logout_session_supported'] = true;
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
