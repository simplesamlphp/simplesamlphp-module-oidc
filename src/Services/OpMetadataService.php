<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;

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
        private readonly ClaimTranslatorExtractor $claimTranslatorExtractor,
    ) {
        $this->initMetadata();
    }

    /**
     * Initialize metadata array.
     * @throws \Exception
     */
    private function initMetadata(): void
    {
        $signer = $this->moduleConfig->getProtocolSigner();

        $this->metadata = [];
        $this->metadata[ClaimsEnum::Issuer->value] = $this->moduleConfig->getIssuer();
        $this->metadata[ClaimsEnum::AuthorizationEndpoint->value] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::Authorization->value);
        $this->metadata[ClaimsEnum::TokenEndpoint->value] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::Token->value);
        $this->metadata[ClaimsEnum::UserinfoEndpoint->value] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::UserInfo->value);
        $this->metadata[ClaimsEnum::EndSessionEndpoint->value] =
        $this->moduleConfig->getModuleUrl(RoutesEnum::EndSession->value);
        $this->metadata[ClaimsEnum::JwksUri->value] = $this->moduleConfig->getModuleUrl(RoutesEnum::Jwks->value);
        $this->metadata[ClaimsEnum::ScopesSupported->value] = array_keys($this->moduleConfig->getScopes());
        $this->metadata[ClaimsEnum::ResponseTypesSupported->value] = ['code', 'token', 'id_token', 'id_token token'];
        $this->metadata[ClaimsEnum::SubjectTypesSupported->value] = ['public'];
        $this->metadata[ClaimsEnum::IdTokenSigningAlgValuesSupported->value] = [
            $signer->algorithmId(),
        ];
        $this->metadata[ClaimsEnum::CodeChallengeMethodsSupported->value] = ['plain', 'S256'];
        $this->metadata[ClaimsEnum::TokenEndpointAuthMethodsSupported->value] = [
            TokenEndpointAuthMethodsEnum::ClientSecretPost->value,
            TokenEndpointAuthMethodsEnum::ClientSecretBasic->value,
            TokenEndpointAuthMethodsEnum::PrivateKeyJwt->value,
        ];
        $this->metadata[ClaimsEnum::TokenEndpointAuthSigningAlgValuesSupported->value] = [
            $signer->algorithmId(),
        ];
        $this->metadata[ClaimsEnum::RequestParameterSupported->value] = true;
        $this->metadata[ClaimsEnum::RequestObjectSigningAlgValuesSupported->value] = [
            'none',
            $signer->algorithmId(),
        ];
        $this->metadata[ClaimsEnum::RequestUriParameterSupported->value] = false;
        $this->metadata[ClaimsEnum::GrantTypesSupported->value] = ['authorization_code', 'refresh_token'];
        $this->metadata[ClaimsEnum::ClaimsParameterSupported->value] = true;
        if (!(empty($acrValuesSupported = $this->moduleConfig->getAcrValuesSupported()))) {
            $this->metadata[ClaimsEnum::AcrValuesSupported->value] = $acrValuesSupported;
        }
        $this->metadata[ClaimsEnum::BackChannelLogoutSupported->value] = true;
        $this->metadata[ClaimsEnum::BackChannelLogoutSessionSupported->value] = true;

        if ($this->moduleConfig->getProtocolDiscoveryShowClaimsSupported()) {
            $claimsSupported = $this->claimTranslatorExtractor->getSupportedClaims();
            $this->metadata[ClaimsEnum::ClaimsSupported->value] = $claimsSupported;
        }
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
