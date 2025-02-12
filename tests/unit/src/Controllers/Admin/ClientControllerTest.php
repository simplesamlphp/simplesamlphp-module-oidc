<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\ClientController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(ClientController::class)]
class ClientControllerTest extends TestCase
{
    protected MockObject $templateFactoryMock;
    protected MockObject $authorizationMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $clientEntityFactoryMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected MockObject $formFactoryMock;
    protected MockObject $sspBridgeMock;
    protected MockObject $sessionMessagesServiceMock;
    protected MockObject $routesMock;
    protected MockObject $helpersMock;
    protected MockObject $loggerMock;
    protected MockObject $clientEntityMock;
    protected MockObject $requestMock;
    protected MockObject $queryInputBagMock;
    protected MockObject $requestInputBagMock;
    protected MockObject $clientFormMock;

    protected array $sampleFormData = [
        'name' => 'Name',
        'description' => 'Description',
        'redirect_uri' => [0 => 'https://example.com/callback',],
        'is_enabled' => true,
        'is_confidential' => true,
        'auth_source' => null,
        'scopes' => [0 => 'openid', 1 => 'profile',],
        'owner' => '',
        'post_logout_redirect_uri' => [0 => 'https://example.com/',],
        'allowed_origin' => [],
        'backchannel_logout_uri' => 'https://example.com/logout',
        'entity_identifier' => 'https://example.com/',
        'client_registration_types' => [0 => 'automatic', 1 => 'explicit',],
        'federation_jwks' => [
            'keys' => [
                0 => [
                    'kty' => 'RSA',
                    'n' => '...',
                    'e' => 'AQAB',
                    'kid' => 'fed123',
                    'use' => 'sig',
                    'alg' => 'RS256',
                ],
            ],
        ],
        'jwks' => [
            'keys' => [
                0 => [
                    'kty' => 'RSA',
                    'n' => '...',
                    'e' => 'AQAB',
                    'kid' => 'prot123',
                    'use' => 'sig',
                    'alg' => 'RS256',
                ],
            ],
        ],
        'jwks_uri' => 'https://example.com/jwks',
        'signed_jwks_uri' => 'https://example.com/signed-jwks',
        'is_federated' => true,
    ];

    protected function setUp(): void
    {
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->clientEntityMock = $this->createMock(ClientEntityInterface::class);

        $this->requestMock = $this->createMock(Request::class);
        $this->queryInputBagMock = $this->createMock(ParameterBag::class);
        $this->requestMock->query = $this->queryInputBagMock;
        $this->requestInputBagMock = $this->createMock(ParameterBag::class);
        $this->requestMock->request = $this->requestInputBagMock;

        $this->clientFormMock = $this->createMock(ClientForm::class);
        $this->formFactoryMock->method('build')->willReturn($this->clientFormMock);
    }

    protected function sut(
        ?TemplateFactory $templateFactory = null,
        ?Authorization $authorization = null,
        ?ClientRepository $clientRepository = null,
        ?ClientEntityFactory $clientEntityFactory = null,
        ?AllowedOriginRepository $allowedOriginRepository = null,
        ?FormFactory $formFactory = null,
        ?SspBridge $sspBridge = null,
        ?SessionMessagesService $sessionMessagesService = null,
        ?Routes $routes = null,
        ?Helpers $helpers = null,
        ?LoggerService $logger = null,
    ): ClientController {
        $templateFactory ??= $this->templateFactoryMock;
        $authorization ??= $this->authorizationMock;
        $clientRepository ??= $this->clientRepositoryMock;
        $clientEntityFactory ??= $this->clientEntityFactoryMock;
        $allowedOriginRepository ??= $this->allowedOriginRepositoryMock;
        $formFactory ??= $this->formFactoryMock;
        $sspBridge ??= $this->sspBridgeMock;
        $sessionMessagesService ??= $this->sessionMessagesServiceMock;
        $routes ??= $this->routesMock;
        $helpers ??= $this->helpersMock;
        $logger ??= $this->loggerMock;

        return new ClientController(
            $templateFactory,
            $authorization,
            $clientRepository,
            $clientEntityFactory,
            $allowedOriginRepository,
            $formFactory,
            $sspBridge,
            $sessionMessagesService,
            $routes,
            $helpers,
            $logger,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdminOrUserWithPermission');
        $this->assertInstanceOf(ClientController::class, $this->sut());
    }

    public function testIndex(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getInt')->with('page')
            ->willReturn(1);
        $this->queryInputBagMock->expects($this->once())->method('getString')->with('q')
            ->willReturn('abc');
        $this->clientRepositoryMock->expects($this->once())->method('findPaginated')
            ->with(1, 'abc', null)->willReturn([
                'items' => [$this->clientEntityMock],
                'numPages' => 1,
                'currentPage' => 1,
                'query' => 'abc',
            ]);
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients.twig');

        $this->sut()->index($this->requestMock);
    }

    public function testShow(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients/show.twig');

        $this->sut()->show($this->requestMock);
    }

    public function testShowThrowsIfClientIdNotProvided(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client ID');

        $this->sut()->show($this->requestMock);
    }

    public function testCanResetSecret(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->requestInputBagMock->expects($this->once())->method('getString')
            ->with('secret')->willReturn('123');
        $this->clientEntityMock->expects($this->once())->method('restoreSecret');
        $this->clientRepositoryMock->expects($this->once())->method('update')
            ->with($this->clientEntityMock);
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('secret'));

        $this->sut()->resetSecret($this->requestMock);
    }

    public function testResetSecretThrowsIfCurrentSecretNotValid(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->requestInputBagMock->expects($this->once())->method('getString')
            ->with('secret')->willReturn('321');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client secret');

        $this->sut()->resetSecret($this->requestMock);
    }

    public function testCanDelete(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->requestInputBagMock->expects($this->once())->method('getString')
            ->with('secret')->willReturn('123');
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('deleted'));
        $this->clientRepositoryMock->expects($this->once())->method('delete')
            ->with($this->clientEntityMock);

        $this->sut()->delete($this->requestMock);
    }

    public function testDeleteThrowsIfCurrentSecretNotValid(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->requestInputBagMock->expects($this->once())->method('getString')
            ->with('secret')->willReturn('321');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client secret');

        $this->sut()->delete($this->requestMock);
    }

    public function testCanAdd(): void
    {
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
        ->willReturn($this->clientEntityMock);

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('added'));

        $this->clientRepositoryMock->expects($this->once())->method('add')
            ->with($this->clientEntityMock);

        $this->allowedOriginRepositoryMock->expects($this->once())->method('set')
            ->with('clientId');

        $this->sut()->add();
    }

    public function testCanShowAddForm(): void
    {
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(false);

        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients/add.twig');

        $this->sut()->add();
    }

    public function testWontAddIfClientIdentifierExists(): void
    {
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($this->clientEntityMock);

        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->createMock(ClientEntityInterface::class));

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('exists'));

        $this->clientRepositoryMock->expects($this->never())->method('add');

        $this->sut()->add();
    }

    public function testWontAddIfClientEntityIdentifierExists(): void
    {
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientEntityMock->method('getEntityIdentifier')->willReturn('https://example.com');
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($this->clientEntityMock);

        $this->clientRepositoryMock->expects($this->once())->method('findByEntityIdentifier')
            ->willReturn($this->createMock(ClientEntityInterface::class));

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('exists'));

        $this->clientRepositoryMock->expects($this->never())->method('add');
        $this->allowedOriginRepositoryMock->expects($this->never())->method('set');

        $this->sut()->add();
    }

    public function testThrowsForInvalidClientData(): void
    {
        $data = $this->sampleFormData;
        $data['name'] = null;
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($data);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('data');

        $this->sut()->add();
    }

    public function testCanEdit(): void
    {
        // Original client.
        // Enum can't be doubled :/.
        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        // Updated client.
        $updatedClientMock = $this->createMock(ClientEntityInterface::class);
        $updatedClientMock->method('getIdentifier')->willReturn('clientId');
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($updatedClientMock);

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('updated'));

        $this->clientRepositoryMock->expects($this->once())->method('update')
            ->with($updatedClientMock);

        $this->allowedOriginRepositoryMock->expects($this->once())->method('set')
            ->with('clientId');

        $this->sut()->edit($this->requestMock);
    }

    public function testWontEditIfClientEntityIdentifierExists(): void
    {
        // Original client.
        // Enum can't be doubled :/.
        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        // Updated client.
        $updatedClientMock = $this->createMock(ClientEntityInterface::class);
        $updatedClientMock->method('getIdentifier')->willReturn('clientId');
        $updatedClientMock->method('getEntityIdentifier')->willReturn('https://example.com');
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturn($updatedClientMock);

        // Additional client with same entity identifier.
        $clientWithEntityIdentifier  = $this->createMock(ClientEntityInterface::class);
        $clientWithEntityIdentifier->method('getEntityIdentifier')->willReturn('https://example.com');
        $this->clientRepositoryMock->expects($this->once())->method('findByEntityIdentifier')
            ->with('https://example.com')
            ->willReturn($clientWithEntityIdentifier);

        $this->clientRepositoryMock->expects($this->never())->method('update');
        $this->allowedOriginRepositoryMock->expects($this->never())->method('set');

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
        ->with($this->stringContains('exists'));

        $this->sut()->edit($this->requestMock);
    }

    public function testCanShowEditForm(): void
    {
        $this->queryInputBagMock->expects($this->once())->method('getString')->willReturn('clientId');
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(false);

        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients/edit.twig');

        $this->sut()->edit($this->requestMock);
    }
}
