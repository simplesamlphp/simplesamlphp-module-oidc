<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Codebooks\ClaimNamesEnum;
use SimpleSAML\Module\oidc\Codebooks\ClaimValues\TypeEnum;
use SimpleSAML\Module\oidc\Codebooks\EntityTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\HttpHeaders;
use SimpleSAML\Module\oidc\Codebooks\HttpHeaderValues\ContentTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use Symfony\Component\HttpFoundation\Response;

class EntityStatementController
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        private readonly JsonWebKeySetService $jsonWebKeySetService,
        private readonly OpMetadataService $opMetadataService,
    ) {
    }

    /**
     * Return the JWS with the OP configuration statement.
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function configuration(): Response
    {
        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimNamesEnum::Type->value, TypeEnum::EntityStatementJwt->value)
            ->relatedTo($this->moduleConfig->getIssuer()) // This is entity configuration (statement about itself).
            ->expiresAt(
                (TimestampGenerator::utcImmutable())->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimNamesEnum::JsonWebKeySet->value,
                ['keys' => array_values($this->jsonWebKeySetService->federationKeys()),],
            )
            ->withClaim(
                ClaimNamesEnum::Metadata->value,
                [
                    EntityTypeEnum::FederationEntity->value => [
                        // Common https://openid.net/specs/openid-federation-1_0.html#name-common-metadata-parameters
                        ...(array_filter(
                            [
                                ClaimNamesEnum::OrganizationName->value => $this->moduleConfig->getOrganizationName(),
                                ClaimNamesEnum::Contacts->value => $this->moduleConfig->getContacts(),
                                ClaimNamesEnum::LogoUri->value => $this->moduleConfig->getLogoUri(),
                                ClaimNamesEnum::PolicyUri->value => $this->moduleConfig->getPolicyUri(),
                                ClaimNamesEnum::HomepageUri->value => $this->moduleConfig->getHomepageUri(),
                            ],
                        )),
                        // TODO mivanci Add when ready. Use ClaimsEnum for keys.
                        // https://openid.net/specs/openid-federation-1_0.html#name-federation-entity
                        //'federation_fetch_endpoint',
                        //'federation_list_endpoint',
                        //'federation_resolve_endpoint',
                        //'federation_trust_mark_status_endpoint',
                        //'federation_trust_mark_list_endpoint',
                        //'federation_trust_mark_endpoint',
                        //'federation_historical_keys_endpoint',
                        // Common https://openid.net/specs/openid-federation-1_0.html#name-common-metadata-parameters
                        //'signed_jwks_uri',
                        //'jwks_uri',
                        //'jwks',
                    ],
                    // TODO mivanci expand OP metadata with federation related claims.
                    EntityTypeEnum::OpenIdProvider->value => $this->opMetadataService->getMetadata(),
                ],
            );

        if (
            is_array($authorityHints = $this->moduleConfig->getFederationAuthorityHints()) &&
            (!empty($authorityHints))
        ) {
            $builder = $builder->withClaim(ClaimNamesEnum::AuthorityHints->value, $authorityHints);
        }

        // TODO mivanci Add remaining claims when ready.
        // * crit
        // * trust_marks
        // * trust_mark_issuers
        // * source_endpoint

        // Note: claims which should only be present in Trust Anchors
        // * trust_mark_owners


        // Note: claims which must not be present in entity configuration:
        // * metadata_policy
        // * constraints
        // * metadata_policy_crit

        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);
        return new Response(
            $jws->toString(),
            200,
            [HttpHeaders::ContentType->value => ContentTypeEnum::ApplicationEntityStatementJwt->value,],
        );
    }
}
