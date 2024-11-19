<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ClientController
{
    public function __construct(
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly ClientRepository $clientRepository,
        protected readonly AllowedOriginRepository $allowedOriginRepository,
    ) {
        $this->authorization->requireAdminOrUserWithPermission(AuthContextService::PERM_CLIENT);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function getClientFromRequest(Request $request): ClientEntityInterface
    {
        ($clientId = $request->query->getString('client_id'))
        || throw new OidcException('Client ID not provided.');

        $authedUserId = $this->authorization->isAdmin() ? null : $this->authorization->getUserId();

        return $this->clientRepository->findById($clientId, $authedUserId) ??
        throw new OidcException('Client not found.');
    }

    public function index(Request $request): Response
    {
        $page = $request->query->getInt('page', 1);
        $query = $request->query->getString('q', '');
        $authedUserId = $this->authorization->isAdmin() ? null : $this->authorization->getUserId();

        $pagination = $this->clientRepository->findPaginated($page, $query, $authedUserId);


        return $this->templateFactory->build(
            'oidc:clients.twig',
            [
                'clients' => $pagination['items'],
                'numPages' => $pagination['numPages'],
                'currentPage' => $pagination['currentPage'],
                'query' => $query,
            ],
            RoutesEnum::AdminClients->value,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function show(Request $request): Response
    {
        $client = $this->getClientFromRequest($request);
        $allowedOrigins = $this->allowedOriginRepository->get($client->getIdentifier());

        // TODO mivanci rename *-ssp.twig templates after removing old ones.
        return $this->templateFactory->build(
            'oidc:clients/show-ssp.twig',
            [
                'client' => $client,
                'allowedOrigins' => $allowedOrigins,
            ],
            RoutesEnum::AdminClients->value,
        );
    }
}
