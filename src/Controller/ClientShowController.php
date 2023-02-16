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

namespace SimpleSAML\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;

class ClientShowController
{
    use AuthenticatedGetClientFromRequestTrait;

    /**
     * @var TemplateFactory
     */
    private $templateFactory;

    /**
     * @var AllowedOriginRepository
     */
    private $allowedOriginRepository;

    public function __construct(
        ClientRepository $clientRepository,
        AllowedOriginRepository $allowedOriginRepository,
        TemplateFactory $templateFactory,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->allowedOriginRepository = $allowedOriginRepository;
        $this->templateFactory = $templateFactory;
        $this->authContextService = $authContextService;
    }

    public function __invoke(ServerRequest $request): \SimpleSAML\XHTML\Template
    {
        $client = $this->getClientFromRequest($request);
        $allowedOrigins = $this->allowedOriginRepository->get($client->getIdentifier());

        return $this->templateFactory->render('oidc:clients/show.twig', [
            'client' => $client,
            'allowedOrigins' => $allowedOrigins
        ]);
    }
}
