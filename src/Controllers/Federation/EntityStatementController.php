<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Federation;

use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\CredentialIssuerMetadataService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Services\VcIssuerMetadataService;
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
use Throwable;

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
        // Constructing these reads no configuration; only asking them for a document does, and below
        // the first is asked only where Verifiable Credentials are enabled, the second inside a net
        // which treats a deployment without credential keys as having nothing to publish.
        protected readonly CredentialIssuerMetadataService $credentialIssuerMetadataService,
        protected readonly VcIssuerMetadataService $vcIssuerMetadataService,
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

        // The two Entity Types OpenID Fed DCP (Appendix B of DIIP v5) defines for a Credential Issuer,
        // each on its own terms. Building either document is what reads the Verifiable Credential
        // settings, so a failure is a deployment whose credential issuance is misconfigured - and whose
        // well-known VCI endpoint fails the same way. Each is contained on its own, like a Trust Mark
        // that can not be fetched below, because an OP's federation registration should not go down
        // with a feature it does not depend on, and verification keys should not be withdrawn over a
        // fault in the issuance metadata. The configuration overview screen is what reports the fault.

        // Under `openid_credential_issuer`, the OpenID4VCI issuer metadata - the same document the
        // well-known endpoint serves, from the same builder: a wallet which finds this Entity Type is to
        // use it and ignore the well-known one, so the two must not be allowed to differ. Only an issuer
        // of credentials is one, so a deployment with Verifiable Credentials off does not claim the
        // Entity Type - and its settings are not read.
        if ($this->moduleConfig->getVciEnabled()) {
            try {
                $payload[ClaimsEnum::Metadata->value][EntityTypesEnum::OpenIdCredentialIssuer->value] =
                $this->credentialIssuerMetadataService->getMetadata();
            } catch (Throwable $exception) {
                $this->loggerService->error(
                    'Could not build the Credential Issuer metadata, so the Entity Configuration is ' .
                    'published without the openid_credential_issuer Entity Type.',
                    ['error' => $exception->getMessage()],
                );
            }
        }

        // Under `vc_issuer`, the keys Digital Credentials are signed with, which is where a verifier
        // checks a credential's `kid` against once it has resolved this entity's Trust Chain. Not behind
        // the issuance switch: a credential in a wallet outlives the switch and needs its key here for
        // as long as it is valid, and what retains the keys is that they stay configured, which is what
        // the installation guide asks of a deployment that turns issuance off. So the keys are published
        // wherever they can be built, and whether failing to build them is a fault depends on the
        // switch: with issuance on it is a broken issuer, with it off it is a deployment which never
        // set credential keys up and has nothing to retain. From here the two cases of the latter - an
        // OP that never issued, and one that issued and has since broken its retained keys - read the
        // same, and the shipped configuration names key files before any exist, so an error would fire
        // on every build of every OP that never issued. The configuration overview screen is what
        // reports a credential key that does not load.
        try {
            $payload[ClaimsEnum::Metadata->value][EntityTypesEnum::VcIssuer->value] =
            $this->vcIssuerMetadataService->getMetadata();
        } catch (Throwable $exception) {
            if ($this->moduleConfig->getVciEnabled()) {
                $this->loggerService->error(
                    'Could not build the credential signing key set, so the Entity Configuration is ' .
                    'published without the vc_issuer Entity Type.',
                    ['error' => $exception->getMessage()],
                );
            } else {
                $this->loggerService->debug(
                    'No credential signing key set to publish under the vc_issuer Entity Type.',
                    ['reason' => $exception->getMessage()],
                );
            }
        }

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
                } catch (Throwable $exception) {
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
