<?php

declare(strict_types=1);

/*
 *        |
 *   \  ___  /                           _________
 *  _  /   \  _    GÉANT                 |  * *  | Co-Funded by
 *     | ~ |       Trust & Identity      | *   * | the European
 *      \_/        Incubator             |__*_*__| Union
 *       =
 *
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Controllers\VerifiableCredentials;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Serves the JSON-LD context document for a specific vc+sd-jwt credential configuration, allowing
 * verifiers to resolve the custom terms used in credential subjects.
 *
 * The endpoint URL is included in the @context array of issued vc+sd-jwt credentials when a
 * context document is configured for the matching credential configuration ID.
 *
 * @see https://www.w3.org/TR/json-ld11/#interpreting-json-as-json-ld
 */
class CredentialJsonLdContextController
{
    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly LoggerService $loggerService,
    ) {
        if (!$this->moduleConfig->getVciEnabled()) {
            $this->loggerService->warning('Verifiable Credential capabilities not enabled.');
            throw OidcServerException::forbidden('Verifiable Credential capabilities not enabled.');
        }
    }

    /**
     * Return the JSON-LD context document for the given credential configuration ID.
     *
     * Responds with HTTP 404 if no context document is configured for the given ID.
     *
     * @param string $credentialConfigurationId URL path parameter injected by the router.
     */
    public function context(string $credentialConfigurationId): Response
    {
        $this->loggerService->debug(
            'CredentialJsonLdContextController::context',
            ['credentialConfigurationId' => $credentialConfigurationId],
        );

        $contextDocument = $this->moduleConfig->getVciCredentialJsonLdContextFor($credentialConfigurationId);

        if ($contextDocument === null) {
            $this->loggerService->warning(
                'CredentialJsonLdContextController::context: No JSON-LD context configured for credential ' .
                'configuration ID.',
                ['credentialConfigurationId' => $credentialConfigurationId],
            );

            return $this->routes->newResponse(null, Response::HTTP_NOT_FOUND);
        }

        return new JsonResponse(
            $contextDocument,
            Response::HTTP_OK,
            ['Content-Type' => 'application/ld+json'],
        );
    }
}
