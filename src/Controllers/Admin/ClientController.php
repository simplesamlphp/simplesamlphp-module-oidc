<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use Nette\Forms\Form;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ParametersEnum;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class ClientController
{
    public function __construct(
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly ClientRepository $clientRepository,
        protected readonly ClientEntityFactory $clientEntityFactory,
        protected readonly AllowedOriginRepository $allowedOriginRepository,
        protected readonly FormFactory $formFactory,
        protected readonly SspBridge $sspBridge,
        protected readonly SessionMessagesService $sessionMessagesService,
        protected readonly Routes $routes,
        protected readonly Helpers $helpers,
        protected readonly LoggerService $logger,
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
        ($clientId = $request->query->getString(ParametersEnum::ClientId->value))
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

        return $this->templateFactory->build(
            'oidc:clients/show.twig',
            [
                'client' => $client,
                'allowedOrigins' => $allowedOrigins,
            ],
            RoutesEnum::AdminClients->value,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function resetSecret(Request $request): Response
    {
        $client = $this->getClientFromRequest($request);

        $oldSecret = $request->request->getString('secret');

        if ($oldSecret !== $client->getSecret()) {
            throw new OidcException('Client secret does not match on secret reset.');
        }

        $client->restoreSecret($this->sspBridge->utils()->random()->generateID());
        $authedUserId = $this->authorization->isAdmin() ? null : $this->authorization->getUserId();
        $this->clientRepository->update($client, $authedUserId);

        $message = Translate::noop('Client secret has been reset.');
        $this->logger->info($message, $client->getState());
        $this->sessionMessagesService->addMessage($message);

        return $this->routes->getRedirectResponseToModuleUrl(
            RoutesEnum::AdminClientsShow->value,
            [ParametersEnum::ClientId->value => $client->getIdentifier()],
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function delete(Request $request): Response
    {
        $client = $this->getClientFromRequest($request);

        $secret = $request->request->getString('secret');

        if ($secret !== $client->getSecret()) {
            throw new OidcException('Client secret does not match on delete.');
        }

        $authedUserId = $this->authorization->isAdmin() ? null : $this->authorization->getUserId();

        $this->clientRepository->delete($client, $authedUserId);

        $message = Translate::noop('Client has been deleted.');
        $this->logger->warning($message, $client->getState());
        $this->sessionMessagesService->addMessage($message);

        return $this->routes->getRedirectResponseToModuleUrl(
            RoutesEnum::AdminClients->value,
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function add(): Response
    {
        $form = $this->formFactory->build(ClientForm::class);

        if ($form->isSuccess()) {
            $createdAt = $this->helpers->dateTime()->getUtc();
            $updatedAt = $createdAt;

            $owner = $this->authorization->isAdmin() ? null : $this->authorization->getUserId();

            $client = $this->buildClientEntityFromFormData(
                $form,
                $this->sspBridge->utils()->random()->generateID(),
                $this->sspBridge->utils()->random()->generateID(),
                RegistrationTypeEnum::Manual,
                $updatedAt,
                $createdAt,
                null,
                $owner,
            );

            if ($this->clientRepository->findById($client->getIdentifier())) {
                $message = Translate::noop('Client with generated ID already exists.');
                $this->logger->warning($message, $client->getState());
                $this->sessionMessagesService->addMessage($message);
            } elseif (
                ($entityIdentifier = $client->getEntityIdentifier()) &&
                $this->clientRepository->findByEntityIdentifier($entityIdentifier)
            ) {
                $message = Translate::noop('Client with given entity identifier already exists.');
                $this->logger->warning($message, $client->getState());
                $this->sessionMessagesService->addMessage($message);
            } else {
                $this->clientRepository->add($client);

                // Also persist allowed origins for this client.
                is_array($allowedOrigins = $form->getValues('array')['allowed_origin'] ?? []) ||
                throw new OidcException('Unexpected value for allowed origins.');
                /** @var string[] $allowedOrigins */
                $this->allowedOriginRepository->set($client->getIdentifier(), $allowedOrigins);
                $message = Translate::noop('Client has been added.');
                $this->logger->info($message, $client->getState());
                $this->sessionMessagesService->addMessage($message);

                return $this->routes->getRedirectResponseToModuleUrl(
                    RoutesEnum::AdminClientsShow->value,
                    [ParametersEnum::ClientId->value => $client->getIdentifier()],
                );
            }
        }

        return $this->templateFactory->build(
            'oidc:clients/add.twig',
            [
                'form' => $form,
                'actionRoute' => $this->routes->urlAdminClientsAdd(),
                'regexUri' => ClientForm::REGEX_URI,
                'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
                'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
                'regexHttpUriPath' => ClientForm::REGEX_HTTP_URI_PATH,
            ],
            RoutesEnum::AdminClients->value,
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \JsonException
     */
    public function edit(Request $request): Response
    {
        $originalClient = $this->getClientFromRequest($request);
        $clientAllowedOrigins = $this->allowedOriginRepository->get($originalClient->getIdentifier());
        $form = $this->formFactory->build(ClientForm::class);

        $clientData = $originalClient->toArray();
        $clientData['allowed_origin'] = $clientAllowedOrigins;
        $form->setDefaults($clientData);

        if ($form->isSuccess()) {
            $updatedAt = $this->helpers->dateTime()->getUtc();

            $updatedClient = $this->buildClientEntityFromFormData(
                $form,
                $originalClient->getIdentifier(),
                $originalClient->getSecret(),
                $originalClient->getRegistrationType(),
                $updatedAt,
                $originalClient->getCreatedAt(),
                $originalClient->getExpiresAt(),
                $originalClient->getOwner(),
            );

            // We have to make sure that the Entity Identifier is unique.
            if (
                ($updatedClientEntityIdentifier = $updatedClient->getEntityIdentifier()) &&
                ($clientByEntityIdentifier = $this->clientRepository->findByEntityIdentifier(
                    $updatedClientEntityIdentifier,
                )) &&
                $updatedClient->getIdentifier() !== $clientByEntityIdentifier->getIdentifier()
            ) {
                $message = Translate::noop('Client with given entity identifier already exists.');
                $this->logger->warning($message, $updatedClient->getState());
                $this->sessionMessagesService->addMessage($message);
            } else {
                $this->clientRepository->update($updatedClient);

                // Also persist allowed origins for this client.
                is_array($allowedOrigins = $form->getValues('array')['allowed_origin'] ?? []) ||
                throw new OidcException('Unexpected value for allowed origins.');
                /** @var string[] $allowedOrigins */
                $this->allowedOriginRepository->set($originalClient->getIdentifier(), $allowedOrigins);

                $this->sessionMessagesService->addMessage(Translate::noop('Client has been updated.'));

                return $this->routes->getRedirectResponseToModuleUrl(
                    RoutesEnum::AdminClientsShow->value,
                    [ParametersEnum::ClientId->value => $originalClient->getIdentifier()],
                );
            }
        }

        return $this->templateFactory->build(
            'oidc:clients/edit.twig',
            [
                'originalClient' => $originalClient,
                'form' => $form,
                'actionRoute' => $this->routes->urlAdminClientsEdit($originalClient->getIdentifier()),
                'regexUri' => ClientForm::REGEX_URI,
                'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
                'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
                'regexHttpUriPath' => ClientForm::REGEX_HTTP_URI_PATH,
            ],
            RoutesEnum::AdminClients->value,
        );
    }

    /**
     * TODO mivanci Move to ClientEntityFactory::fromRegistrationData on dynamic client registration implementation.
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    protected function buildClientEntityFromFormData(
        Form $form,
        string $identifier,
        string $secret,
        RegistrationTypeEnum $registrationType,
        \DateTimeImmutable $updatedAt,
        ?\DateTimeImmutable $createdAt = null,
        ?\DateTimeImmutable $expiresAt = null,
        ?string $owner = null,
    ): ClientEntityInterface {
        /** @var array $data */
        $data = $form->getValues('array');

        if (
            !is_string($data[ClientEntity::KEY_NAME]) ||
            !is_string($data[ClientEntity::KEY_DESCRIPTION]) ||
            !is_array($data[ClientEntity::KEY_REDIRECT_URI]) ||
            !is_array($data[ClientEntity::KEY_SCOPES]) ||
            !is_array($data[ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI])
        ) {
            throw new OidcException('Invalid Client Entity data');
        }

        /** @var string[] $redirectUris */
        $redirectUris = $data[ClientEntity::KEY_REDIRECT_URI];
        /** @var string[] $scopes */
        $scopes = $data[ClientEntity::KEY_SCOPES];
        /** @var string[] $postLogoutRedirectUris */
        $postLogoutRedirectUris = $data[ClientEntity::KEY_POST_LOGOUT_REDIRECT_URI];
        /** @var ?string[] $clientRegistrationTypes */
        $clientRegistrationTypes = is_array($data[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES]) ?
        $data[ClientEntity::KEY_CLIENT_REGISTRATION_TYPES] : null;
        /** @var ?array[] $federationJwks */
        $federationJwks = is_array($data[ClientEntity::KEY_FEDERATION_JWKS]) ?
        $data[ClientEntity::KEY_FEDERATION_JWKS] : null;
        /** @var ?array[] $jwks */
        $jwks = is_array($data[ClientEntity::KEY_JWKS]) ? $data[ClientEntity::KEY_JWKS] : null;
        $jwksUri = empty($data[ClientEntity::KEY_JWKS_URI]) ? null : (string)$data[ClientEntity::KEY_JWKS_URI];
        $signedJwksUri = empty($data[ClientEntity::KEY_SIGNED_JWKS_URI]) ?
        null : (string)$data[ClientEntity::KEY_SIGNED_JWKS_URI];
        $isFederated = (bool)$data[ClientEntity::KEY_IS_FEDERATED];

        return $this->clientEntityFactory->fromData(
            $identifier,
            $secret,
            $data['name'],
            $data['description'],
            $redirectUris,
            $scopes,
            (bool) $data['is_enabled'],
            (bool) $data['is_confidential'],
            empty($data['auth_source']) ? null : (string)$data['auth_source'],
            $owner,
            $postLogoutRedirectUris,
            empty($data['backchannel_logout_uri']) ? null : (string)$data['backchannel_logout_uri'],
            empty($data['entity_identifier']) ? null : (string)$data['entity_identifier'],
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
        );
    }
}
