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

namespace SimpleSAML\Module\oidc\Controller\Client;

use JsonException;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\XHTML\Template;

class DeleteController
{
    use AuthenticatedGetClientFromRequestTrait;

    public function __construct(
        ClientRepository $clientRepository,
        private readonly TemplateFactory $templateFactory,
        private readonly SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->authContextService = $authContextService;
    }

    /**
     * @throws ConfigurationError|BadRequest|NotFound|Exception|OidcServerException|JsonException
     * @throws \Exception
     */
    public function __invoke(ServerRequest $request): Template|RedirectResponse
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = empty($body['secret']) ? null : (string)$body['secret'];
        $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();
        if ('POST' === mb_strtoupper($request->getMethod())) {
            if (!$clientSecret) {
                throw new BadRequest('Client secret is missing.');
            }

            if ($clientSecret !== $client->getSecret()) {
                throw new BadRequest('Client secret is invalid.');
            }

            $this->clientRepository->delete($client, $authedUser);
            $this->messages->addMessage('{oidc:client:removed}');

            return new RedirectResponse((new HTTP())->addURLParameters('index.php', []));
        }

        return $this->templateFactory->render('oidc:clients/delete.twig', [
            'client' => $client,
        ]);
    }
}
