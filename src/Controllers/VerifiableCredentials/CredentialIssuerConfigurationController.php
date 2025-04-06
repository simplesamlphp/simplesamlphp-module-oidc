<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\Response;

class CredentialIssuerConfigurationController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
    ) {
    }

    public function configuration(): Response
    {
        $configuration = [
            ClaimsEnum::CredentialIssuer->value => $this->moduleConfig->getIssuer(),
        ];

        return $this->routes->newJsonResponse($configuration);
    }
}
