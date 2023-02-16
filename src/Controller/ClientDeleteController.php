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

use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\HTTP;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;

class ClientDeleteController
{
    use AuthenticatedGetClientFromRequestTrait;

    /**
     * @var \SimpleSAML\Module\oidc\Factories\TemplateFactory
     */
    private $templateFactory;

    /**
     * @var \SimpleSAML\Module\oidc\Services\SessionMessagesService
     */
    private $messages;

    public function __construct(
        ClientRepository $clientRepository,
        TemplateFactory $templateFactory,
        SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->templateFactory = $templateFactory;
        $this->messages = $messages;
        $this->authContextService = $authContextService;
    }

    /**
     * @return \Laminas\Diactoros\Response\RedirectResponse|\SimpleSAML\XHTML\Template
     */
    public function __invoke(ServerRequest $request)
    {
        $client = $this->getClientFromRequest($request);
        $body = $request->getParsedBody();
        $clientSecret = $body['secret'] ?? null;
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
