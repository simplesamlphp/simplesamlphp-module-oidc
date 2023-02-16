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
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;

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

    /**
     * @var AuthContextService
     */
    private $authContextService;

    public function __construct(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
        $this->authContextService = $authContextService;
    }

    public function __invoke(ServerRequest $request): \SimpleSAML\XHTML\Template
    {
        $queryParams = $request->getQueryParams();

        $page = array_key_exists('page', $queryParams) ? (int) $queryParams['page'] : 1;
        $query = array_key_exists('q', $queryParams) ? (string) $queryParams['q'] : '';
        $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();
        $pagination = $this->clientRepository->findPaginated($page, $query, $authedUser);

        return $this->templateFactory->render('oidc:clients/index.twig', [
            'clients' => $pagination['items'],
            'numPages' => $pagination['numPages'],
            'currentPage' => $pagination['currentPage'],
            'query' => $query,
        ]);
    }
}
