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

use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use Laminas\Diactoros\ServerRequest;

class ClientIndexController
{
    /**
     * @var ClientRepository
     */
    private $clientRepository;

    /**
     * @var TemplateFactory
     */
    private $templateFactory;

    public function __construct(ClientRepository $clientRepository, TemplateFactory $templateFactory)
    {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
    }

    public function __invoke(ServerRequest $request): \SimpleSAML\XHTML\Template
    {
        $queryParams = $request->getQueryParams();

        $page = array_key_exists('page', $queryParams) ? (int) $queryParams['page'] : 1;
        $query = array_key_exists('q', $queryParams) ? (string) $queryParams['q'] : '';

        $pagination = $this->clientRepository->findPaginated($page, $query);

        return $this->templateFactory->render('oidc:clients/index.twig', [
            'clients' => $pagination['items'],
            'numPages' => $pagination['numPages'],
            'currentPage' => $pagination['currentPage'],
            'query' => $query,
        ]);
    }
}
