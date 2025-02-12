<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Helpers;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

class Client
{
    public function __construct(protected Http $http)
    {
    }

    /**
     * @throws \JsonException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function getFromRequest(
        ServerRequestInterface $request,
        ClientRepository $clientRepository,
    ): ClientEntityInterface {
        $params = $this->http->getAllRequestParams($request);
        $clientId = empty($params['client_id']) ? null : (string)$params['client_id'];

        if (!is_string($clientId)) {
            throw new OidcException('Client ID is missing.');
        }

        $client = $clientRepository->findById($clientId);

        if (!$client) {
            throw new OidcException('Client not found.');
        }

        return $client;
    }
}
