<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controller\Federation;

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
     * Return the JWS with the OP configuration statement. openid-federation
     * @return Response
     */
    public function configuration(): Response
    {
        // TODO mivanci Adjust JsonWebTokenBuilderService to accommodate new federation capabilities
        $jws = '';
        return new Response($jws);
    }
}
