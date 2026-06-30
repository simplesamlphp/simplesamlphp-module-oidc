<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\SupportedClientMetadata;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

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
        private readonly Routes $routes,
    ) {
        $this->initMetadata();
    }

    /**
     * Initialize metadata array.
     * @throws \Exception
     */
    private function initMetadata(): void
    {
        // Signature algorithms that this OP can use to sign JWS artifacts.
        $protocolSignatureAlgorithmNames = $this->moduleConfig
            ->getProtocolSignatureKeyPairBag()
            ->getAllAlgorithmNamesUnique();

        // Signature algorithms that this OP can use to validate signature on
        // signed JWS artifacts.
        $supportedSignatureAlgorithmNames = $this->moduleConfig
            ->getSupportedAlgorithms()
            ->getSignatureAlgorithmBag()
            ->getAllNamesUnique();

        $this->metadata = [];
        $this->metadata[ClaimsEnum::Issuer->value] = $this->moduleConfig->getIssuer();
        $this->metadata[ClaimsEnum::AuthorizationEndpoint->value] =
        $this->routes->getModuleUrl(RoutesEnum::Authorization->value);
        $this->metadata[ClaimsEnum::TokenEndpoint->value] =
        $this->routes->getModuleUrl(RoutesEnum::Token->value);
        $this->metadata[ClaimsEnum::UserinfoEndpoint->value] =
        $this->routes->getModuleUrl(RoutesEnum::UserInfo->value);
        $this->metadata[ClaimsEnum::EndSessionEndpoint->value] =
        $this->routes->getModuleUrl(RoutesEnum::EndSession->value);
        $this->metadata[ClaimsEnum::JwksUri->value] = $this->routes->getModuleUrl(RoutesEnum::Jwks->value);
        if ($this->moduleConfig->getDcrEnabled()) {
            $this->metadata[ClaimsEnum::RegistrationEndpoint->value] =
            $this->routes->getModuleUrl(RoutesEnum::Registration->value);
        }
        $this->metadata[ClaimsEnum::ScopesSupported->value] = array_keys($this->moduleConfig->getScopes());
        $this->metadata[ClaimsEnum::ResponseTypesSupported->value] = SupportedClientMetadata::responseTypes();
        $this->metadata[ClaimsEnum::SubjectTypesSupported->value] = ['public'];
        $this->metadata[ClaimsEnum::IdTokenSigningAlgValuesSupported->value] = $protocolSignatureAlgorithmNames;
        $this->metadata[ClaimsEnum::CodeChallengeMethodsSupported->value] = ['plain', 'S256'];
        $this->metadata[ClaimsEnum::TokenEndpointAuthMethodsSupported->value] =
        SupportedClientMetadata::tokenEndpointAuthMethods();
        $this->metadata[ClaimsEnum::TokenEndpointAuthSigningAlgValuesSupported->value] =
        $supportedSignatureAlgorithmNames;
        $this->metadata[ClaimsEnum::RequestParameterSupported->value] = true;
        $this->metadata[ClaimsEnum::RequestObjectSigningAlgValuesSupported->value] = [
            'none',
            ...$supportedSignatureAlgorithmNames,
        ];
        $this->metadata[ClaimsEnum::RequestUriParameterSupported->value] =
        $this->moduleConfig->getRequestUriParameterSupported();
        // The https request_uri values must be pre-registered for the client
        // (request_uris client metadata).
        $this->metadata[ClaimsEnum::RequireRequestUriRegistration->value] = true;
        $this->metadata[ClaimsEnum::PushedAuthorizationRequestEndpoint->value] =
        $this->routes->getModuleUrl(RoutesEnum::PushedAuthorizationRequest->value);
        $this->metadata[ClaimsEnum::RequirePushedAuthorizationRequests->value] =
        $this->moduleConfig->getRequirePushedAuthorizationRequests();

        $grantTypesSupported = SupportedClientMetadata::grantTypes();
        if ($this->moduleConfig->getVciEnabled()) {
            // The VCI pre-authorized_code grant is an OP capability advertised in discovery, but it is not a
            // per-client registerable grant type (it is not part of SupportedClientMetadata).
            $grantTypesSupported[] = GrantTypesEnum::PreAuthorizedCode->value;
        }
        $this->metadata[ClaimsEnum::GrantTypesSupported->value] = $grantTypesSupported;

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

        $this->metadata[ClaimsEnum::ResponseModesSupported->value] = $this->moduleConfig->getSupportedResponseModes();

        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-oauth-20-authorization-serv
        // OPTIONAL
        // pre-authorized_grant_anonymous_access_supported // TODO mivanci Make configurable
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
