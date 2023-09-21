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

namespace SimpleSAML\Module\oidc\Controller;

use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Traits\AuthenticatedGetClientFromRequestTrait;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Utils\HTTP;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\XHTML\Template;

class ClientEditController
{
    use AuthenticatedGetClientFromRequestTrait;

    public function __construct(
        ClientRepository $clientRepository,
        protected AllowedOriginRepository $allowedOriginRepository,
        private TemplateFactory $templateFactory,
        private FormFactory $formFactory,
        private SessionMessagesService $messages,
        AuthContextService $authContextService
    ) {
        $this->clientRepository = $clientRepository;
        $this->authContextService = $authContextService;
    }

    /**
     * @throws BadRequest|Exception|NotFound|\Exception
     */
    public function __invoke(ServerRequest $request): Template|RedirectResponse
    {
        $client = $this->getClientFromRequest($request);
        $clientAllowedOrigins = $this->allowedOriginRepository->get($client->getIdentifier());

        /** @var ClientForm $form  */
        $form = $this->formFactory->build(ClientForm::class);
        $formAction = $request->withQueryParams(['client_id' => $client->getIdentifier()])->getRequestTarget();
        $form->setAction($formAction);
        $clientData = $client->toArray();
        $clientData['allowed_origin'] = $clientAllowedOrigins;
        $form->setDefaults($clientData);
        $authedUser = $this->authContextService->isSspAdmin() ? null : $this->authContextService->getAuthUserId();

        if ($form->isSuccess()) {
            $data = $form->getValues();

            if (
                !is_string($data['name']) ||
                !is_string($data['description']) ||
                !is_array($data['redirect_uri']) ||
                !is_array($data['scopes']) ||
                !is_array($data['post_logout_redirect_uri']) ||
                !is_array($data['allowed_origin'])
            ) {
                throw OidcServerException::serverError('Invalid Client Entity data');
            }

            /** @var string[] $redirectUris */
            $redirectUris = $data['redirect_uri'];
            /** @var string[] $scopes */
            $scopes = $data['scopes'];
            /** @var string[] $postLogoutRedirectUris */
            $postLogoutRedirectUris = $data['post_logout_redirect_uri'];
            /** @var string[] $allowedOrigins */
            $allowedOrigins = $data['allowed_origin'];

            $this->clientRepository->update(ClientEntity::fromData(
                $client->getIdentifier(),
                $client->getSecret(),
                $data['name'],
                $data['description'],
                $redirectUris,
                $scopes,
                (bool) $data['is_enabled'],
                (bool) $data['is_confidential'],
                empty($data['auth_source']) ? null : (string)$data['auth_source'],
                $client->getOwner(),
                $postLogoutRedirectUris,
                empty($data['backchannel_logout_uri']) ? null : (string)$data['backchannel_logout_uri']
            ), $authedUser);

            // Also persist allowed origins for this client.
            $this->allowedOriginRepository->set($client->getIdentifier(), $allowedOrigins);

            $this->messages->addMessage('{oidc:client:updated}');

            return new RedirectResponse(
                (new HTTP())->addURLParameters('show.php', ['client_id' => $client->getIdentifier()])
            );
        }

        return $this->templateFactory->render('oidc:clients/edit.twig', [
            'form' => $form,
            'regexUri' => ClientForm::REGEX_URI,
            'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
            'regexHttpUri' => ClientForm::REGEX_HTTP_URI
        ]);
    }
}
