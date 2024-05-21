<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\JsonWebTokenBuilderService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use Symfony\Component\HttpFoundation\Response;

class EntityStatementController
{
    public function __construct(
        private readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
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
            ->withHeader('typ', 'entity-statement+jwt')
        ;
        $jws = $this->jsonWebTokenBuilderService->getSignedFederationJwt($builder);
        return new Response($jws->toString());
    }
}
