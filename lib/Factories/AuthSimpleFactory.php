<?php

/*
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

namespace SimpleSAML\Module\oidc\Factories;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Controller\Traits\GetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class AuthSimpleFactory
{
    use GetClientFromRequestTrait;

    /**
     * @var ConfigurationService
     */
    private $configurationService;

    public function __construct(
        ClientRepository $clientRepository,
        ConfigurationService $configurationService
    ) {
        $this->clientRepository = $clientRepository;
        $this->configurationService = $configurationService;
    }

    /**
     * @codeCoverageIgnore
     */
    public function build(ServerRequestInterface $request): Simple
    {
        $client = $this->getClientFromRequest($request);
        $authSource = $this->resolveAuthSource($client);

        return new Simple($authSource);
    }

    /**
     * Get auth source defined on the client. If not set on the client, get the default auth source defined in config.
     *
     * @param ClientEntityInterface $client
     * @return string
     * @throws \Exception
     */
    private function resolveAuthSource(ClientEntityInterface $client): string
    {
        $defaultAuthSource = $this->configurationService->getOpenIDConnectConfiguration()->getString('auth');
        return $client->getAuthSource() ?? $defaultAuthSource;
    }
}
