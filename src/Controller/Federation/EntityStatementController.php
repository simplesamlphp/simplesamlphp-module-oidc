<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Codebooks\ClaimNamesEnum;
use SimpleSAML\Module\oidc\Codebooks\ClaimValues\TypeEnum;
use SimpleSAML\Module\oidc\Codebooks\EntityTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
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
     * @return Response
     * @throws OidcServerException
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

        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);
        return new Response($jws->toString());
    }
}
