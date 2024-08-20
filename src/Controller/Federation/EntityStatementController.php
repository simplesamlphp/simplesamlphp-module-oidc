<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Codebooks\ClaimNamesEnum;
use SimpleSAML\Module\oidc\Codebooks\ClaimValues\ClientRegistrationTypesEnum;
use SimpleSAML\Module\oidc\Codebooks\ClaimValues\TypeEnum;
use SimpleSAML\Module\oidc\Codebooks\EntityTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\ErrorsEnum;
use SimpleSAML\Module\oidc\Codebooks\HttpHeadersEnum;
use SimpleSAML\Module\oidc\Codebooks\HttpHeaderValues\ContentTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class EntityStatementController
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        private readonly JsonWebKeySetService $jsonWebKeySetService,
        private readonly OpMetadataService $opMetadataService,
        private readonly ClientRepository $clientRepository,
    ) {
    }

    /**
     * Return the JWS with the OP configuration statement.
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function configuration(): Response
    {
        // TODO mivanci header and each JWK must have 'kid'.
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
                        ClaimNamesEnum::FederationFetchEndpoint->value =>
                            $this->moduleConfig->getModuleUrl(RoutesEnum::OpenIdFederationFetch->value),
                        // TODO mivanci Add when ready. Use ClaimsEnum for keys.
                        // https://openid.net/specs/openid-federation-1_0.html#name-federation-entity
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
                    // OP metadata with federation related claims.
                    EntityTypeEnum::OpenIdProvider->value => [
                        ...$this->opMetadataService->getMetadata(),
                        ClaimNamesEnum::ClientRegistrationTypesSupported->value => [
                            ClientRegistrationTypesEnum::Automatic->value,
                        ],
                    ],
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
            [HttpHeadersEnum::ContentType->value => ContentTypeEnum::ApplicationEntityStatementJwt->value,],
        );
    }

    public function fetch(Request $request): Response
    {
        $issuer = $request->query->get(ClaimNamesEnum::Issuer->value);

        if (empty($issuer)) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::InvalidRequest->value,
                sprintf('Missing parameter %s', ClaimNamesEnum::Issuer->value),
                400,
            );
        }

        $issuer = (string) $issuer;

        if (!hash_equals($issuer, $this->moduleConfig->getIssuer())) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::InvalidIssuer->value,
                sprintf('Invalid issuer (%s)', $issuer),
                404,
            );
        }

        $subject = $request->query->get(ClaimNamesEnum::Subject->value);

        // If the subject is not set, we are required to return the issuer entity configuration.
        if (empty($subject)) {
            return $this->configuration();
        }

        /** @var non-empty-string $subject */
        $subject = (string)$subject;
        $client = $this->clientRepository->findByEntityIdentifier($subject);
        if (empty($client)) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::NotFound->value,
                sprintf('Subject not found (%s)', $subject),
                404,
            );
        }
        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimNamesEnum::Type->value, TypeEnum::EntityStatementJwt->value)
            ->relatedTo($subject)
            ->expiresAt(
                (TimestampGenerator::utcImmutable())->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimNamesEnum::JsonWebKeySet->value,
                ['keys' => array_values($this->jsonWebKeySetService->federationKeys()),],
            )
            ->withClaim(
                ClaimNamesEnum::Metadata->value,
                [
                    EntityTypeEnum::OpenIdRelyingParty->value => [
                        ClaimNamesEnum::ClientName->value => $client->getName(),
                        ClaimNamesEnum::ClientId->value => $client->getIdentifier(),
                        ClaimNamesEnum::RedirectUris->value => $client->getRedirectUris(),
                        ClaimNamesEnum::Scope->value => implode(' ', $client->getScopes()),
                        ClaimNamesEnum::ClientRegistrationTypes->value => $client->getClientRegistrationTypes(),
                        // Optional claims...
                        ...(array_filter(
                            [
                                ClaimNamesEnum::BackChannelLogoutUri->value => $client->getBackChannelLogoutUri(),
                                ClaimNamesEnum::PostLogoutRedirectUris->value => $client->getPostLogoutRedirectUri(),
                            ],
                        )),
                        // TODO mivanci Continue
                        // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
                        // https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata
                    ],
                ],
            );

        // TODO mivanci ?Enforce through metadata policy:
        // ?response_types, grant_types...


        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);
        return new Response(
            $jws->toString(),
            200,
            [HttpHeadersEnum::ContentType->value => ContentTypeEnum::ApplicationEntityStatementJwt->value,],
        );
    }

    private function prepareJsonErrorResponse(string $error, string $description, int $httpCode = 500): JsonResponse
    {
        return new JsonResponse(
            [
                'error' => $error,
                'error_description' => $description,
            ],
            $httpCode,
        );
    }
}
