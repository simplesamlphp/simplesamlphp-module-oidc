<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ContentTypeEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypeEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypeEnum;
use SimpleSAML\OpenID\Codebooks\RequestAuthenticationMethodsEnum;
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
        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimsEnum::Typ->value, JwtTypeEnum::EntityStatementJwt->value)
            ->relatedTo($this->moduleConfig->getIssuer()) // This is entity configuration (statement about itself).
            ->expiresAt(
                (TimestampGenerator::utcImmutable())->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimsEnum::Jwks->value,
                ['keys' => array_values($this->jsonWebKeySetService->federationKeys()),],
            )
            ->withClaim(
                ClaimsEnum::Metadata->value,
                [
                    EntityTypeEnum::FederationEntity->value => [
                        // Common https://openid.net/specs/openid-federation-1_0.html#name-common-metadata-parameters
                        ...(array_filter(
                            [
                                ClaimsEnum::OrganizationName->value => $this->moduleConfig->getOrganizationName(),
                                ClaimsEnum::Contacts->value => $this->moduleConfig->getContacts(),
                                ClaimsEnum::LogoUri->value => $this->moduleConfig->getLogoUri(),
                                ClaimsEnum::PolicyUri->value => $this->moduleConfig->getPolicyUri(),
                                ClaimsEnum::HomepageUri->value => $this->moduleConfig->getHomepageUri(),
                            ],
                        )),
                        ClaimsEnum::FederationFetchEndpoint->value =>
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
                    // OP metadata with additional federation related claims.
                    EntityTypeEnum::OpenIdProvider->value => [
                        ...$this->opMetadataService->getMetadata(),
                        ClaimsEnum::ClientRegistrationTypesSupported->value => [
                            ClientRegistrationTypesEnum::Automatic->value,
                        ],
                        ClaimsEnum::RequestAuthenticationMethodsSupported->value => [
                            ClaimsEnum::AuthorizationEndpoint->value => [
                                RequestAuthenticationMethodsEnum::RequestObject->value,
                            ],
                        ],
                        ClaimsEnum::RequestAuthenticationSigningAlgValuesSupported->value => [
                            $this->moduleConfig->getProtocolSigner()->algorithmId(),
                        ],
                    ],
                ],
            );

        if (
            is_array($authorityHints = $this->moduleConfig->getFederationAuthorityHints()) &&
            (!empty($authorityHints))
        ) {
            $builder = $builder->withClaim(ClaimsEnum::AuthorityHints->value, $authorityHints);
        }

        // Remaining claims, add if / when ready.
        // * crit
        // * trust_marks
        // * trust_mark_issuers
        // * source_endpoint

        // Note: claims which should only be present in Trust Anchors
        // * trust_mark_owners

        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);
        return new Response(
            $jws->toString(),
            200,
            [HttpHeadersEnum::ContentType->value => ContentTypeEnum::ApplicationEntityStatementJwt->value,],
        );
    }

    public function fetch(Request $request): Response
    {
        $issuer = $request->query->get(ClaimsEnum::Iss->value);

        if (empty($issuer)) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::InvalidRequest->value,
                sprintf('Missing parameter %s', ClaimsEnum::Iss->value),
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

        $subject = $request->query->get(ClaimsEnum::Sub->value);

        if (empty($subject)) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::InvalidRequest->value,
                sprintf('Missing parameter %s', ClaimsEnum::Sub->value),
                400,
            );
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

        $jwks = $client->getFederationJwks();
        if (empty($jwks)) {
            return $this->prepareJsonErrorResponse(
                ErrorsEnum::InvalidClient->value,
                sprintf('Subject does not contain JWKS claim (%s)', $subject),
                401,
            );
        }

        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimsEnum::Typ->value, JwtTypeEnum::EntityStatementJwt->value)
            ->relatedTo($subject)
            ->expiresAt(
                (TimestampGenerator::utcImmutable())->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimsEnum::Jwks->value,
                $jwks,
            )
            ->withClaim(
                ClaimsEnum::Metadata->value,
                [
                    EntityTypeEnum::OpenIdRelyingParty->value => [
                        ClaimsEnum::ClientName->value => $client->getName(),
                        ClaimsEnum::ClientId->value => $client->getIdentifier(),
                        ClaimsEnum::RedirectUris->value => $client->getRedirectUris(),
                        ClaimsEnum::Scope->value => implode(' ', $client->getScopes()),
                        ClaimsEnum::ClientRegistrationTypes->value => $client->getClientRegistrationTypes(),
                        // Optional claims...
                        ...(array_filter(
                            [
                                ClaimsEnum::BackChannelLogoutUri->value => $client->getBackChannelLogoutUri(),
                                ClaimsEnum::PostLogoutRedirectUris->value => $client->getPostLogoutRedirectUri(),
                            ],
                        )),
                        // TODO mivanci Continue
                        // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
                        // https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata
                    ],
                ],
            );

        // Note: claims which can be present in subordinate statements:
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
