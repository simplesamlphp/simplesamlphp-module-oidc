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

use Laminas\Diactoros\Response\RedirectResponse;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;
use SimpleSAML\XHTML\Template;

class CreateController
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly AllowedOriginRepository $allowedOriginRepository,
        private readonly TemplateFactory $templateFactory,
        private readonly FormFactory $formFactory,
        private readonly SessionMessagesService $messages,
        private readonly AuthContextService $authContextService,
        private readonly Helpers $helpers,
        private readonly ClientEntityFactory $clientEntityFactory,
    ) {
    }

    /**
     * @return \Laminas\Diactoros\Response\RedirectResponse|\SimpleSAML\XHTML\Template
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function __invoke(): Template|RedirectResponse
    {
        /** @var ClientForm $form */
        $form = $this->formFactory->build(ClientForm::class);
        $form->setAction('./new.php');


        if ($form->isSuccess()) {
            $client = $form->getValues();
            $client['id'] = (new Random())->generateID();
            $client['secret'] = (new Random())->generateID();
            if (!$this->authContextService->isSspAdmin()) {
                $client['owner'] = $this->authContextService->getAuthUserId();
            }

            if (
                !is_string($client['name']) ||
                !is_string($client['description']) ||
                !is_array($client['redirect_uri']) ||
                !is_array($client['scopes']) ||
                !is_array($client['post_logout_redirect_uri']) ||
                !is_array($client['allowed_origin'])
            ) {
                throw OidcServerException::serverError('Invalid Client Entity data');
            }

            /** @var string[] $redirectUris */
            $redirectUris = $client['redirect_uri'];
            /** @var string[] $scopes */
            $scopes = $client['scopes'];
            /** @var string[] $postLogoutRedirectUris */
            $postLogoutRedirectUris = $client['post_logout_redirect_uri'];
            /** @var string[] $allowedOrigins */
            $allowedOrigins = $client['allowed_origin'];
            /** @var string[] $clientRegistrationTypes */
            $clientRegistrationTypes = is_array($client['client_registration_types']) ?
            $client['client_registration_types'] : null;
            /** @var ?array[] $federationJwks */
            $federationJwks = is_array($client['federation_jwks']) ? $client['federation_jwks'] : null;
            /** @var ?array[] $jwks */
            $jwks = is_array($client['jwks']) ? $client['jwks'] : null;
            $jwksUri = empty($client['jwks_uri']) ? null : (string)$client['jwks_uri'];
            $signedJwksUri = empty($client['signed_jwks_uri']) ? null : (string)$client['signed_jwks_uri'];

            $registrationType = RegistrationTypeEnum::Manual;
            $createdAt = $this->helpers->dateTime()->getUtc();
            $updatedAt = $createdAt;
            $expiresAt = null;
            $isFederated = (bool)$client['is_federated'];

            $this->clientRepository->add($this->clientEntityFactory->fromData(
                $client['id'],
                $client['secret'],
                $client['name'],
                $client['description'],
                $redirectUris,
                $scopes,
                (bool)$client['is_enabled'],
                (bool)$client['is_confidential'],
                empty($client['auth_source']) ? null : (string)$client['auth_source'],
                empty($client['owner']) ? null : (string)$client['owner'],
                $postLogoutRedirectUris,
                empty($client['backchannel_logout_uri']) ? null : (string)$client['backchannel_logout_uri'],
                empty($client['entity_identifier']) ? null : (string)$client['entity_identifier'],
                $clientRegistrationTypes,
                $federationJwks,
                $jwks,
                $jwksUri,
                $signedJwksUri,
                $registrationType,
                $updatedAt,
                $createdAt,
                $expiresAt,
                $isFederated,
            ));

            // Also persist allowed origins for this client.
            $this->allowedOriginRepository->set($client['id'], $allowedOrigins);

            $this->messages->addMessage('{oidc:client:added}');

            return new RedirectResponse((new HTTP())->addURLParameters('show.php', ['client_id' => $client['id']]));
        }

        return $this->templateFactory->build('oidc:clients/new-old.twig', [
            'form' => $form,
            'regexUri' => ClientForm::REGEX_URI,
            'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
            'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
            'regexHttpUriPath' => ClientForm::REGEX_HTTP_URI_PATH,
        ]);
    }
}
