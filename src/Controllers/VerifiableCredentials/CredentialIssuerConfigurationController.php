<?php

declare(strict_types=1);

/*
 *        |
 *   \  ___  /                           _________
 *  _  /   \  _    GÉANT                 |  * *  | Co-Funded by
 *     | ~ |       Trust & Identity      | *   * | the European
 *      \_/        Incubator             |__*_*__| Union
 *       =
 */

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\CredentialIssuerMetadataService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\Response;

/**
 * The `.well-known/openid-credential-issuer` endpoint.
 *
 * The document itself is built by CredentialIssuerMetadataService, which also serves it to the Entity
 * Configuration, so that what a wallet reads at this location and what it reads in the federation
 * metadata are one document.
 */
class CredentialIssuerConfigurationController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
        // Constructing the service reads no configuration, and the container resolves every constructor
        // argument before the guard below runs, so taking it here does not answer a request this
        // endpoint refuses outright by failing on Verifiable Credential settings it never needed.
        protected readonly CredentialIssuerMetadataService $credentialIssuerMetadataService,
    ) {
        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\OpenID\Exceptions\DidException
     * @throws \SimpleSAML\OpenID\Exceptions\DestinationPolicyException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \Exception
     */
    public function configuration(): Response
    {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata-p
        return $this->routes->newJsonResponse($this->credentialIssuerMetadataService->getMetadata());
    }
}
