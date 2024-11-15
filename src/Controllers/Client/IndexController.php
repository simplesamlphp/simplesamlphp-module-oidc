<?php

declare(strict_types=1);

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

namespace SimpleSAML\Module\oidc\Controllers\Client;

use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\XHTML\Template;

class IndexController
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly TemplateFactory $templateFactory,
        private readonly AuthContextService $authContextService,
    ) {
    }

    /**
     * @throws \Exception
     * @throws \SimpleSAML\Error\Exception
     */
    public function __invoke(ServerRequest $request): Template
    {
        $queryParams = $request->getQueryParams();

        $page = array_key_exists('page', $queryParams) ? (int) $queryParams['page'] : 1;
        $query = array_key_exists('q', $queryParams) ? (string) $queryParams['q'] : '';
        $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();
        $pagination = $this->clientRepository->findPaginated($page, $query, $authedUser);

        return $this->templateFactory->build('oidc:clients/index.twig', [
            'clients' => $pagination['items'],
            'numPages' => $pagination['numPages'],
            'currentPage' => $pagination['currentPage'],
            'query' => $query,
        ]);
    }
}
