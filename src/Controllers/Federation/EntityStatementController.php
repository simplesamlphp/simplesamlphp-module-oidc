<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Federation;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ContentTypesEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwks;
use Symfony\Component\HttpFoundation\Response;

class EntityStatementController
{
    protected const string KEY_OP_ENTITY_CONFIGURATION_STATEMENT = 'op_entity_configuration_statement';
    protected const string KEY_RP_SUBORDINATE_ENTITY_STATEMENT = 'rp_subordinate_entity_statement';

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Jwks $jwks,
        protected readonly OpMetadataService $opMetadataService,
        protected readonly Helpers $helpers,
        protected readonly Routes $routes,
        protected readonly Federation $federation,
        protected readonly LoggerService $loggerService,
        protected readonly ?FederationCache $federationCache,
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

        $currentTimestamp = $this->helpers->dateTime()->getUtc()->getTimestamp();

        $jwks = $this->jwks->jwksDecoratorFactory()->fromJwkDecorators(
            ...$this->moduleConfig->getFederationSignatureKeyPairBag()->getAllPublicKeys(),
        )->jsonSerialize();

        $payload = [
            ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Iat->value => $currentTimestamp,
            ClaimsEnum::Jti->value => $this->federation->helpers()->random()->string(),
            // This is entity configuration (statement about itself).
            ClaimsEnum::Sub->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Exp->value => $this->helpers->dateTime()->getUtc()->add(
                $this->moduleConfig->getFederationEntityStatementDuration(),
            )->getTimestamp(),
            ClaimsEnum::Jwks->value => $jwks,
            ClaimsEnum::Metadata->value => [
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
        ];

        if (
            is_array($authorityHints = $this->moduleConfig->getFederationAuthorityHints()) &&
            (!empty($authorityHints))
        ) {
            $payload[ClaimsEnum::AuthorityHints->value] = $authorityHints;
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
            $payload[ClaimsEnum::TrustMarks->value] = $trustMarks;
        }

        // TODO v7 mivanci Continue
        // Remaining claims, add if / when ready.
        // * crit

        $signingKeyPair = $this->moduleConfig
            ->getFederationSignatureKeyPairBag()
            ->getFirstOrFail();

        $header = [
            ClaimsEnum::Kid->value => $signingKeyPair->getKeyPair()->getKeyId(),
        ];

        /** @psalm-suppress ArgumentTypeCoercion */
        $entityConfigurationToken = $this->federation->entityStatementFactory()->fromData(
            $signingKeyPair->getKeyPair()->getPrivateKey(),
            $signingKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        )->getToken();

        $this->federationCache?->set(
            $entityConfigurationToken,
            $this->moduleConfig->getFederationEntityStatementCacheDurationForProduced(),
            self::KEY_OP_ENTITY_CONFIGURATION_STATEMENT,
            $this->moduleConfig->getIssuer(),
        );

        return $this->prepareEntityStatementResponse($entityConfigurationToken);
    }

    protected function prepareEntityStatementResponse(string $entityStatementToken): Response
    {
        return $this->routes->newResponse(
            $entityStatementToken,
            200,
            [
                HttpHeadersEnum::ContentType->value => ContentTypesEnum::ApplicationEntityStatementJwt->value,
                'Access-Control-Allow-Origin' => '*',
            ],
        );
    }
}
