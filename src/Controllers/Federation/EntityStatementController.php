<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Federation;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ContentTypesEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class EntityStatementController
{
    protected const KEY_OP_ENTITY_CONFIGURATION_STATEMENT = 'op_entity_configuration_statement';
    protected const KEY_RP_SUBORDINATE_ENTITY_STATEMENT = 'rp_subordinate_entity_statement';

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        private readonly JsonWebKeySetService $jsonWebKeySetService,
        private readonly OpMetadataService $opMetadataService,
        private readonly ClientRepository $clientRepository,
        private readonly Helpers $helpers,
        private readonly Routes $routes,
        private readonly Federation $federation,
        private readonly LoggerService $loggerService,
        private readonly ?FederationCache $federationCache,
    ) {
        if (!$this->moduleConfig->getFederationEnabled()) {
            throw OidcServerException::forbidden('federation capabilities not enabled');
        }
    }

    /**
     * Return the JWS with the OP configuration statement.
     *
     * @return \Symfony\Component\HttpFoundation\Response
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \ReflectionException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function configuration(): Response
    {
        $cachedEntityConfigurationToken = $this->federationCache?->get(
            null,
            self::KEY_OP_ENTITY_CONFIGURATION_STATEMENT,
            $this->moduleConfig->getIssuer(),
        );

        if (!is_null($cachedEntityConfigurationToken)) {
            return $this->prepareEntityStatementResponse((string)$cachedEntityConfigurationToken);
        }

        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimsEnum::Typ->value, JwtTypesEnum::EntityStatementJwt->value)
            ->relatedTo($this->moduleConfig->getIssuer()) // This is entity configuration (statement about itself).
            ->expiresAt(
                $this->helpers->dateTime()->getUtc()->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimsEnum::Jwks->value,
                ['keys' => array_values($this->jsonWebKeySetService->federationKeys()),],
            )
            ->withClaim(
                ClaimsEnum::Metadata->value,
                [
                    EntityTypesEnum::FederationEntity->value => [
                        // Common https://openid.net/specs/openid-federation-1_0.html#name-common-metadata-parameters
                        ...(array_filter(
                            [
                                ClaimsEnum::OrganizationName->value => $this->moduleConfig->getOrganizationName(),
                                ClaimsEnum::DisplayName->value => $this->moduleConfig->getDisplayName(),
                                ClaimsEnum::Description->value => $this->moduleConfig->getDescription(),
                                ClaimsEnum::Keywords->value => $this->moduleConfig->getKeywords(),
                                ClaimsEnum::Contacts->value => $this->moduleConfig->getContacts(),
                                ClaimsEnum::LogoUri->value => $this->moduleConfig->getLogoUri(),
                                ClaimsEnum::PolicyUri->value => $this->moduleConfig->getPolicyUri(),
                                ClaimsEnum::InformationUri->value => $this->moduleConfig->getInformationUri(),
                                ClaimsEnum::OrganizationUri->value => $this->moduleConfig->getOrganizationUri(),
                            ],
                        )),
                        ClaimsEnum::FederationFetchEndpoint->value => $this->routes->urlFederationFetch(),
                        ClaimsEnum::FederationListEndpoint->value => $this->routes->urlFederationList(),
                        // TODO v7 mivanci Add when ready. Use ClaimsEnum for keys.
                        // https://openid.net/specs/openid-federation-1_0.html#name-federation-entity
                        //'federation_resolve_endpoint',
                        //'federation_trust_mark_status_endpoint',
                        //'federation_trust_mark_list_endpoint',
                        //'federation_trust_mark_endpoint',
                        //'federation_historical_keys_endpoint',
                        //'endpoint_auth_signing_alg_values_supported'
                        // Common https://openid.net/specs/openid-federation-1_0.html#name-common-metadata-parameters
                        //'signed_jwks_uri',
                        //'jwks_uri',
                        //'jwks',
                    ],
                    // OP metadata with additional federation related claims.
                    EntityTypesEnum::OpenIdProvider->value => [
                        ...$this->opMetadataService->getMetadata(),
                        ClaimsEnum::ClientRegistrationTypesSupported->value => [
                            ClientRegistrationTypesEnum::Automatic->value,
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

        $trustMarks = [];

        if (
            is_array($trustMarkTokens = $this->moduleConfig->getFederationTrustMarkTokens()) &&
            (!empty($trustMarkTokens))
        ) {
            $trustMarks = array_map(function (string $token): array {
                $trustMarkEntity = $this->federation->trustMarkFactory()->fromToken($token);

                if ($trustMarkEntity->getSubject() !== $this->moduleConfig->getIssuer()) {
                    throw OidcServerException::serverError(sprintf(
                        'Trust Mark %s is not intended for this entity.',
                        $trustMarkEntity->getTrustMarkType(),
                    ));
                }

                return [
                    ClaimsEnum::TrustMarkType->value => $trustMarkEntity->getTrustMarkType(),
                    ClaimsEnum::TrustMark->value => $token,
                ];
            }, $trustMarkTokens);
        }

        if (
            is_array($dynamicTrustMarks = $this->moduleConfig->getFederationDynamicTrustMarks()) &&
            (!empty($dynamicTrustMarks))
        ) {
            /**
             * @var non-empty-string $trustMarkType
             * @var non-empty-string $trustMarkIssuerId
             */
            foreach ($dynamicTrustMarks as $trustMarkType => $trustMarkIssuerId) {
                try {
                    $trustMarkIssuerConfigurationStatement = $this->federation->entityStatementFetcher()
                        ->fromCacheOrWellKnownEndpoint($trustMarkIssuerId);

                    $trustMarkEntity = $this->federation->trustMarkFetcher()->fromCacheOrFederationTrustMarkEndpoint(
                        $trustMarkType,
                        $this->moduleConfig->getIssuer(),
                        $trustMarkIssuerConfigurationStatement,
                    );

                    $trustMarks[] = [
                        ClaimsEnum::TrustMarkType->value => $trustMarkType,
                        ClaimsEnum::TrustMark->value => $trustMarkEntity->getToken(),
                    ];
                } catch (\Throwable $exception) {
                    $this->loggerService->error(
                        'Error fetching Trust Mark: ' . $exception->getMessage(),
                        [
                            'trustMarkType' => $trustMarkType,
                            'subjectId' => $this->moduleConfig->getIssuer(),
                            'trustMarkIssuerId' => $trustMarkIssuerId,
                        ],
                    );
                }
            }
        }

        if (!empty($trustMarks)) {
            $builder = $builder->withClaim(ClaimsEnum::TrustMarks->value, $trustMarks);
        }

        // TODO v7 mivanci Continue
        // Remaining claims, add if / when ready.
        // * crit

        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);

        $entityConfigurationToken = $jws->toString();

        $this->federationCache?->set(
            $entityConfigurationToken,
            $this->moduleConfig->getFederationEntityStatementCacheDurationForProduced(),
            self::KEY_OP_ENTITY_CONFIGURATION_STATEMENT,
            $this->moduleConfig->getIssuer(),
        );

        return $this->prepareEntityStatementResponse($entityConfigurationToken);
    }

    public function fetch(Request $request): Response
    {
        $subject = $request->query->getString(ClaimsEnum::Sub->value);

        if (empty($subject)) {
            return $this->routes->newJsonErrorResponse(
                ErrorsEnum::InvalidRequest->value,
                sprintf('Missing parameter %s', ClaimsEnum::Sub->value),
                400,
            );
        }

        /** @var non-empty-string $subject */

        $cachedSubordinateStatement = $this->federationCache?->get(
            null,
            self::KEY_RP_SUBORDINATE_ENTITY_STATEMENT,
            $subject,
        );

        if (!is_null($cachedSubordinateStatement)) {
            return $this->prepareEntityStatementResponse((string)$cachedSubordinateStatement);
        }

        $client = $this->clientRepository->findFederatedByEntityIdentifier($subject);
        if (empty($client)) {
            return $this->routes->newJsonErrorResponse(
                ErrorsEnum::NotFound->value,
                sprintf('Subject not found (%s)', $subject),
                404,
            );
        }

        $jwks = $client->getFederationJwks();
        if (empty($jwks)) {
            return $this->routes->newJsonErrorResponse(
                ErrorsEnum::InvalidClient->value,
                sprintf('Subject does not contain JWKS claim (%s)', $subject),
                401,
            );
        }

        $builder = $this->jsonWebTokenBuilderService->getFederationJwtBuilder()
            ->withHeader(ClaimsEnum::Typ->value, JwtTypesEnum::EntityStatementJwt->value)
            ->relatedTo($subject)
            ->expiresAt(
                $this->helpers->dateTime()->getUtc()->add($this->moduleConfig->getFederationEntityStatementDuration()),
            )->withClaim(
                ClaimsEnum::Jwks->value,
                $jwks,
            )
            ->withClaim(
                ClaimsEnum::Metadata->value,
                [
                    EntityTypesEnum::OpenIdRelyingParty->value => [
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
                        // TODO v7 mivanci Continue
                        // https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata
                        // https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#client-metadata
                    ],
                ],
            );

        // TODO v7 mivanci Continue
        // Note: claims which can be present in subordinate statements:
        // * metadata_policy
        // * constraints
        // * metadata_policy_crit

        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);

        $subordinateStatementToken = $jws->toString();

        $this->federationCache?->set(
            $subordinateStatementToken,
            $this->moduleConfig->getFederationEntityStatementCacheDurationForProduced(),
            self::KEY_RP_SUBORDINATE_ENTITY_STATEMENT,
            $subject,
        );

        return $this->prepareEntityStatementResponse($subordinateStatementToken);
    }

    protected function prepareEntityStatementResponse(string $entityStatementToken): Response
    {
        return $this->routes->newResponse(
            $entityStatementToken,
            200,
            [HttpHeadersEnum::ContentType->value => ContentTypesEnum::ApplicationEntityStatementJwt->value,],
        );
    }
}
