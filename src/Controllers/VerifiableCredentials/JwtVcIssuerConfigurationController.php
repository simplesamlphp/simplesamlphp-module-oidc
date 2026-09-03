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

use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class JwtVcIssuerConfigurationController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
        if (!$this->moduleConfig->getVciEnabled() && !$this->isNeededByIssuedCredentials()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }


    /**
     * Whether credentials already issued are verified by way of this document.
     *
     * Under the `https` issuer identity, an SD-JWT VC states its issuer as a URL and a verifier finds
     * the key set to check it against by fetching exactly this document. Withdrawing it when issuance
     * is switched off would therefore not stop credentials being issued - it would stop the ones
     * already issued from being verified, which is the same reason the Status List and DID document
     * endpoints are not gated on that switch either.
     */
    protected function isNeededByIssuedCredentials(): bool
    {
        try {
            return $this->moduleConfig->getVciIssuerIdentifierMode() === VciIssuerIdentifierModeEnum::Https;
        } catch (Throwable) {
            // Reported on the configuration overview screen, which owns that error. Here the
            // conservative reading is the one this endpoint had before the identity was configurable.
            return false;
        }
    }


    public function configuration(): Response
    {
        $configuration = [
            ClaimsEnum::Issuer->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::JwksUri->value => $this->routes->getModuleUrl(RoutesEnum::Jwks->value),
        ];

        // Cross origin reads are allowed, as they are on the key set and the DID document. A browser
        // based wallet or verifier holding a credential from another origin has to read this document
        // to find the key set to check it against, and without the header the browser refuses the read
        // -- so the credential fails verification at a deployment which serves everything correctly.
        return $this->routes->newJsonResponse(
            $configuration,
            headers: ['Access-Control-Allow-Origin' => '*'],
        );
    }
}
