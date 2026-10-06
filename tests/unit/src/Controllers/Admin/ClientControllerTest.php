<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils as SspBridgeUtils;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\ClientController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Client as ClientHelper;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Utils\Random as SspRandom;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(ClientController::class)]
#[AllowMockObjectsWithoutExpectations]
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
        ClientEntity::KEY_ALLOWED_RESPONSE_MODES => ['query', 'fragment', 'form_post'],
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
        $request = Request::create(
            '/',
            'GET',
            ['page' => '1', 'q' => 'abc'],
        );

        $this->clientRepositoryMock->expects($this->once())->method('findPaginated')
            ->with(1, 'abc', null)->willReturn([
                'items' => [$this->clientEntityMock],
                'numPages' => 1,
                'currentPage' => 1,
                'query' => 'abc',
            ]);
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients.twig');

        $this->sut()->index($request);
    }


    public function testShow(): void
    {
        $request = Request::create(
            '/',
            'GET',
            ['client_id' => 'clientId'],
        );

        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients/show.twig');

        $this->sut()->show($request);
    }


    public function testShowThrowsIfClientIdNotProvided(): void
    {
        $request = Request::create(
            '/',
            'GET',
            [],
        );

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client ID');

        $this->sut()->show($request);
    }


    public function testCanResetSecret(): void
    {
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '123'],
        );

        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->clientEntityMock->expects($this->once())->method('restoreSecret');
        $this->clientRepositoryMock->expects($this->once())->method('update')
            ->with($this->clientEntityMock);
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('secret'));

        $this->sut()->resetSecret($request);
    }


    public function testResetSecretThrowsIfCurrentSecretNotValid(): void
    {
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '321'],
        );

        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client secret');

        $this->sut()->resetSecret($request);
    }


    public function testCanDelete(): void
    {
        $request = Request::create(
            '/delete?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '123'],
        );

        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('deleted'));
        $this->clientRepositoryMock->expects($this->once())->method('delete')
            ->with($this->clientEntityMock);

        $this->sut()->delete($request);
    }


    public function testDeleteThrowsIfCurrentSecretNotValid(): void
    {
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '321'],
        );

        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client secret');

        $this->sut()->delete($request);
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function changingActionProvider(): array
    {
        return [
            'edit' => ['edit'],
            'secret reset' => ['resetSecret'],
            'delete' => ['delete'],
        ];
    }


    /**
     * The module keeps rebuilding the VCI Generic Client from its configuration, writing over whatever an
     * administrator did to it, so no change is made: the administrator is sent back to its page with a message
     * saying why. Everything the change would go through is set up to let it through, so that only the refusal
     * stops it.
     */
    #[DataProvider('changingActionProvider')]
    public function testTheGenericClientIsNotChanged(string $action): void
    {
        $request = Request::create(
            '/' . $action . '?client_id=vci_generic',
            'POST',
            ['client_id' => 'vci_generic', 'secret' => '123'],
        );

        $genericClientMock = $this->createMock(ClientEntityInterface::class);
        $genericClientMock->method('isGeneric')->willReturn(true);
        $genericClientMock->method('getIdentifier')->willReturn('vci_generic');
        $genericClientMock->method('getSecret')->willReturn('123');
        $genericClientMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $genericClientMock->expects($this->never())->method('restoreSecret');
        $this->clientRepositoryMock->method('findById')->with('vci_generic')->willReturn($genericClientMock);
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityFactoryMock->method('fromData')->willReturn($this->clientEntityMock);

        $this->clientRepositoryMock->expects($this->never())->method('update');
        $this->clientRepositoryMock->expects($this->never())->method('delete');
        $this->allowedOriginRepositoryMock->expects($this->never())->method('set');
        $this->templateFactoryMock->expects($this->never())->method('build');
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with('The VCI Generic Client is managed by the module, and can not be changed here.');
        $this->routesMock->expects($this->once())->method('newRedirectResponseToModuleUrl')
            ->with(RoutesEnum::AdminClientsShow->value, ['client_id' => 'vci_generic']);

        $this->sut()->{$action}($request);
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

        $this->clientRepositoryMock->expects($this->once())->method('isIdentifierTakenIgnoringCase')
            ->with('clientId')
            ->willReturn(true);

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('generated ID already exists'));

        $this->clientRepositoryMock->expects($this->never())->method('add');

        $this->sut()->add();
    }


    public function testAnAdministratorAddsAClientWithAGivenIdAndSecret(): void
    {
        $givenSecret = str_repeat('s', 32);
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $this->clientFormMock->expects($this->once())->method('forNewClient');
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn([
            ...$this->sampleFormData,
            ClientForm::FIELD_CLIENT_ID => 'MozillaThunderbird',
            ClientForm::FIELD_CLIENT_SECRET => $givenSecret,
        ]);
        $this->clientEntityMock->method('getIdentifier')->willReturn('MozillaThunderbird');
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->with('MozillaThunderbird', $givenSecret)
            ->willReturn($this->clientEntityMock);
        $this->clientRepositoryMock->expects($this->once())->method('isIdentifierTakenIgnoringCase')
            ->with('MozillaThunderbird')
            ->willReturn(false);

        $this->clientRepositoryMock->expects($this->once())->method('add')->with($this->clientEntityMock);

        $this->sut()->add();
    }


    /**
     * What an administrator leaves empty is generated, each value on its own.
     */
    public function testAnAdministratorMayGiveTheIdAlone(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $this->generatedIdentifierIs('_generated');
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn([
            ...$this->sampleFormData,
            ClientForm::FIELD_CLIENT_ID => 'MozillaThunderbird',
            ClientForm::FIELD_CLIENT_SECRET => null,
        ]);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->with('MozillaThunderbird', '_generated')
            ->willReturn($this->clientEntityMock);

        $this->sut()->add();
    }


    public function testAGivenIdTakenInAnyLetterCaseIsRefused(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn([
            ...$this->sampleFormData,
            ClientForm::FIELD_CLIENT_ID => 'MozillaThunderbird',
        ]);
        $this->clientEntityMock->method('getIdentifier')->willReturn('MozillaThunderbird');
        $this->clientEntityFactoryMock->method('fromData')->willReturn($this->clientEntityMock);
        $this->clientRepositoryMock->method('isIdentifierTakenIgnoringCase')->willReturn(true);

        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with($this->stringContains('letter case'));
        $this->clientRepositoryMock->expects($this->never())->method('add');

        $this->sut()->add();
    }


    /**
     * A user managing their own clients has no fields for the ID and secret; a request carrying them anyway gets
     * generated ones.
     */
    public function testAClientIdAndSecretFromSomebodyOtherThanAnAdministratorAreIgnored(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(false);
        $this->authorizationMock->method('getUserId')->willReturn('user@example.org');
        $this->generatedIdentifierIs('_generated');
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn([
            ...$this->sampleFormData,
            ClientForm::FIELD_CLIENT_ID => 'MozillaThunderbird',
            ClientForm::FIELD_CLIENT_SECRET => str_repeat('s', 32),
        ]);

        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->with('_generated', '_generated')
            ->willReturn($this->clientEntityMock);

        $this->sut()->add();
    }


    public function testTheAddFormIsTheFormForANewClient(): void
    {
        $this->clientFormMock->expects($this->once())->method('forNewClient');
        $this->clientFormMock->method('isSuccess')->willReturn(false);

        $this->sut()->add();
    }


    public function testAnAdministratorSetsAGivenSecret(): void
    {
        $givenSecret = str_repeat('s', 32);
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '123', 'new_secret' => " $givenSecret "],
        );
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $clientHelperMock = $this->createMock(ClientHelper::class);
        $clientHelperMock->expects($this->once())->method('problemsWithGivenSecret')->with($givenSecret)
            ->willReturn([]);
        $this->helpersMock->method('client')->willReturn($clientHelperMock);

        $this->clientEntityMock->expects($this->once())->method('restoreSecret')->with($givenSecret);
        $this->clientRepositoryMock->expects($this->once())->method('update')->with($this->clientEntityMock, null);
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with('Client secret has been set.');

        $this->sut()->resetSecret($request);
    }


    public function testAGivenSecretWhichCanNotBeUsedLeavesTheSecretAsItIs(): void
    {
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '123', 'new_secret' => 'short'],
        );
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $this->clientEntityMock->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $clientHelperMock = $this->createMock(ClientHelper::class);
        $clientHelperMock->method('problemsWithGivenSecret')->willReturn(['The client secret is too short.']);
        $this->helpersMock->method('client')->willReturn($clientHelperMock);

        $messages = [];
        $this->sessionMessagesServiceMock->method('addMessage')->willReturnCallback(
            function (string $message) use (&$messages): void {
                $messages[] = $message;
            },
        );
        $this->clientEntityMock->expects($this->never())->method('restoreSecret');
        $this->clientRepositoryMock->expects($this->never())->method('update');

        $this->sut()->resetSecret($request);

        $this->assertSame(['Client secret has not been changed.', 'The client secret is too short.'], $messages);
    }


    public function testAGivenSecretFromSomebodyOtherThanAnAdministratorIsIgnored(): void
    {
        $request = Request::create(
            '/resetSecret?client_id=clientId',
            'POST',
            ['client_id' => 'clientId', 'secret' => '123', 'new_secret' => str_repeat('s', 32)],
        );
        $this->authorizationMock->method('isAdmin')->willReturn(false);
        $this->authorizationMock->method('getUserId')->willReturn('user@example.org');
        $this->generatedIdentifierIs('_generated');
        $this->clientEntityMock->method('getSecret')->willReturn('123');
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $this->helpersMock->expects($this->never())->method('client');

        $this->clientEntityMock->expects($this->once())->method('restoreSecret')->with('_generated');
        $this->sessionMessagesServiceMock->expects($this->once())->method('addMessage')
            ->with('Client secret has been reset.');

        $this->sut()->resetSecret($request);
    }


    public function testTheClientPageOffersAGivenSecretToAnAdministratorOnly(): void
    {
        $request = Request::create('/', 'GET', ['client_id' => 'clientId']);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);
        $isAdmin = true;
        $this->authorizationMock->method('isAdmin')->willReturnCallback(function () use (&$isAdmin): bool {
            return $isAdmin;
        });
        $this->authorizationMock->method('getUserId')->willReturn('user@example.org');

        $offered = [];
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (string $template, array $data) use (&$offered): Template {
                $offered[] = $data['setsGivenSecret'];
                return $this->createMock(Template::class);
            },
        );

        $this->sut()->show($request);
        $isAdmin = false;
        $this->sut()->show($request);

        $this->assertSame([true, false], $offered);
    }


    protected function generatedIdentifierIs(string $identifier): void
    {
        $randomMock = $this->createMock(SspRandom::class);
        $randomMock->method('generateID')->willReturn($identifier);
        $sspUtilsMock = $this->createMock(SspBridgeUtils::class);
        $sspUtilsMock->method('random')->willReturn($randomMock);
        $this->sspBridgeMock->method('utils')->willReturn($sspUtilsMock);
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
        $request = Request::create(
            '/edit?client_id=clientId',
            'GET',
            ['client_id' => 'clientId', 'secret' => '123'],
        );

        // Original client.
        // Enum can't be doubled :/.
        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
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

        $this->sut()->edit($request);
    }


    /**
     * A user managing their own clients saves their client with the owner filter, as a secret reset and a delete
     * do; an administrator saves any client.
     */
    public function testAnEditIsSavedForTheOwnerOnly(): void
    {
        $request = Request::create('/edit?client_id=clientId', 'GET', ['client_id' => 'clientId']);
        $this->authorizationMock->method('isAdmin')->willReturn(false);
        $this->authorizationMock->method('getUserId')->willReturn('user@example.org');
        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientId', 'user@example.org')->willReturn($this->clientEntityMock);
        $updatedClientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->sampleFormData);
        $this->clientEntityFactoryMock->method('fromData')->willReturn($updatedClientMock);

        $this->clientRepositoryMock->expects($this->once())->method('update')
            ->with($updatedClientMock, 'user@example.org');

        $this->sut()->edit($request);
    }


    public function testWontEditIfClientEntityIdentifierExists(): void
    {
        $request = Request::create(
            '/edit?client_id=clientId',
            'GET',
            ['client_id' => 'clientId', 'secret' => '123'],
        );

        // Original client.
        // Enum can't be doubled :/.
        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
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

        $this->sut()->edit($request);
    }


    /**
     * The form's submitted values with the administrator-only properties set as an administrator's form returns
     * them; a request from anybody else could carry the same.
     */
    protected function formDataWithAdminOnlyProperties(): array
    {
        return [
            ...$this->sampleFormData,
            ClientEntity::KEY_AUTH_PROC_FILTERS => [60 => ['class' => 'core:PHP', 'code' => '']],
            ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => true,
            ClientEntity::KEY_INTROSPECTION_RESOURCE_SERVER => true,
            ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS => ['deny' => []],
        ];
    }


    /**
     * Edits the client `clientId`, whose record holds the given extra metadata, with the given form values, and
     * returns the extra metadata the updated client is built with.
     */
    protected function extraMetadataSavedByEdit(array $storedExtraMetadata, array $formData): array
    {
        $request = Request::create('/edit?client_id=clientId', 'GET', ['client_id' => 'clientId']);

        $this->clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientEntityMock->method('getExtraMetadata')->willReturn($storedExtraMetadata);
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientEntityMock);

        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($formData);

        $savedExtraMetadata = null;
        $updatedClientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturnCallback(function (mixed ...$arguments) use (&$savedExtraMetadata, $updatedClientMock) {
                $savedExtraMetadata = $arguments[23];
                return $updatedClientMock;
            });
        $this->clientRepositoryMock->expects($this->once())->method('update')->with($updatedClientMock);

        $this->sut()->edit($request);

        $this->assertIsArray($savedExtraMetadata);
        return $savedExtraMetadata;
    }


    public function testAnAdministratorSetsTheAdministratorOnlyProperties(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);

        $saved = $this->extraMetadataSavedByEdit([], $this->formDataWithAdminOnlyProperties());

        $this->assertSame([60 => ['class' => 'core:PHP', 'code' => '']], $saved[ClientEntity::KEY_AUTH_PROC_FILTERS]);
        $this->assertTrue($saved[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN]);
        $this->assertTrue($saved[ClientEntity::KEY_INTROSPECTION_RESOURCE_SERVER]);
        $this->assertSame(['deny' => []], $saved[ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS]);
    }


    /**
     * dpop_bound_access_tokens is saved as the form gives it, and as false when the form gives nothing.
     */
    public function testAnEditSavesDpopBoundAccessTokens(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);

        $saved = $this->extraMetadataSavedByEdit([], [...$this->sampleFormData, 'dpop_bound_access_tokens' => true]);

        $this->assertTrue($saved['dpop_bound_access_tokens']);
    }


    public function testAnEditWithoutDpopBoundAccessTokensSavesFalse(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);
        $formData = $this->sampleFormData;
        unset($formData['dpop_bound_access_tokens']);

        $saved = $this->extraMetadataSavedByEdit(['dpop_bound_access_tokens' => true], $formData);

        $this->assertFalse($saved['dpop_bound_access_tokens']);
    }


    /**
     * An administrator removing the foreign issuer list removes it from the record.
     */
    public function testAnAdministratorRemovesTheForeignIssuerList(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(true);

        $saved = $this->extraMetadataSavedByEdit(
            [ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS => ['deny' => ['https://node-a.example.org']]],
            [...$this->sampleFormData, ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS => null],
        );

        $this->assertArrayNotHasKey(ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS, $saved);
        $this->assertFalse($saved[ClientEntity::KEY_INTROSPECTION_RESOURCE_SERVER]);
    }


    /**
     * A user managing their own clients through the `client` permission neither sets nor changes the
     * administrator-only properties, whatever the request carries: the client keeps what it has.
     */
    public function testSomebodyOtherThanAnAdministratorKeepsTheStoredAdministratorOnlyProperties(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(false);
        $stored = [
            ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN => false,
            ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS => ['allow' => ['https://node-a.example.org']],
        ];

        $saved = $this->extraMetadataSavedByEdit($stored, $this->formDataWithAdminOnlyProperties());

        $this->assertArrayNotHasKey(ClientEntity::KEY_AUTH_PROC_FILTERS, $saved);
        $this->assertFalse($saved[ClientEntity::KEY_ADD_CLAIMS_TO_ID_TOKEN]);
        $this->assertArrayNotHasKey(ClientEntity::KEY_INTROSPECTION_RESOURCE_SERVER, $saved);
        $this->assertSame(
            ['allow' => ['https://node-a.example.org']],
            $saved[ClientEntity::KEY_INTROSPECTION_FOREIGN_ISSUERS],
        );
    }


    /**
     * A client such a user adds has none of them.
     */
    public function testAClientAddedBySomebodyOtherThanAnAdministratorHasNoAdministratorOnlyProperties(): void
    {
        $this->authorizationMock->method('isAdmin')->willReturn(false);
        $this->authorizationMock->method('getUserId')->willReturn('user@example.org');
        $this->clientFormMock->method('isSuccess')->willReturn(true);
        $this->clientFormMock->method('getValues')->willReturn($this->formDataWithAdminOnlyProperties());
        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');

        $savedExtraMetadata = null;
        $this->clientEntityFactoryMock->expects($this->once())->method('fromData')
            ->willReturnCallback(function (mixed ...$arguments) use (&$savedExtraMetadata) {
                $savedExtraMetadata = $arguments[23];
                return $this->clientEntityMock;
            });
        $this->clientRepositoryMock->expects($this->once())->method('add');

        $this->sut()->add();

        $this->assertIsArray($savedExtraMetadata);
        foreach (ClientEntity::ADMIN_ONLY_METADATA_KEYS as $adminOnlyMetadataKey) {
            $this->assertArrayNotHasKey($adminOnlyMetadataKey, $savedExtraMetadata, $adminOnlyMetadataKey);
        }
    }


    public function testCanShowEditForm(): void
    {
        $request = Request::create(
            '/edit?client_id=clientId',
            'GET',
            ['client_id' => 'clientId', 'secret' => '123'],
        );

        $this->clientEntityMock->method('getIdentifier')->willReturn('clientId');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(false);

        $this->templateFactoryMock->expects($this->once())->method('build')
            ->with('oidc:clients/edit.twig');

        $this->sut()->edit($request);
    }
}
