<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controller\Client;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\Client\CreateController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\Client\CreateController
 */
class CreateControllerTest extends TestCase
{
    protected MockObject $clientRepositoryMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $formFactoryMock;
    protected MockObject $sessionMessageServiceMock;
    protected MockObject $authContextServiceMock;
    protected MockObject $clientFormMock;
    protected Stub $serverRequestStub;
    protected Stub $templateStub;
    protected MockObject $helpersMock;
    protected MockObject $clientEntityFactoryMock;
    protected MockObject $clientEntityMock;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->sessionMessageServiceMock = $this->createMock(SessionMessagesService::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);

        $this->clientFormMock = $this->createMock(ClientForm::class);
        $this->serverRequestStub = $this->createStub(ServerRequest::class);
        $this->templateStub = $this->createStub(Template::class);

        $this->helpersMock = $this->createMock(Helpers::class);

        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
    }

    public function testCanInstantiate(): void
    {
        $controller = $this->mock();
        $this->assertInstanceOf(CreateController::class, $controller);
    }

    protected function mock(): CreateController
    {
        return new CreateController(
            $this->clientRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->templateFactoryMock,
            $this->formFactoryMock,
            $this->sessionMessageServiceMock,
            $this->authContextServiceMock,
            $this->helpersMock,
            $this->clientEntityFactoryMock,
        );
    }

    /**
     * @throws \Exception
     */
    public function testCanShowNewClientForm(): void
    {
        $this->clientFormMock
            ->expects($this->once())
            ->method('setAction')
            ->with($this->anything());
        $this->clientFormMock
            ->expects($this->once())
            ->method('isSuccess')
            ->willReturn(false);

        $this->templateFactoryMock
            ->expects($this->once())
            ->method('build')
            ->with('oidc:clients/new.twig', [
                'form' => $this->clientFormMock,
                'regexUri' => ClientForm::REGEX_URI,
                'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
                'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
                'regexHttpUriPath' => ClientForm::REGEX_HTTP_URI_PATH,
            ])
            ->willReturn($this->templateStub);

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->with($this->equalTo(ClientForm::class))
            ->willReturn($this->clientFormMock);

        $controller = $this->mock();
        $this->assertSame($this->templateStub, $controller->__invoke());
    }

    /**
     * @throws \Exception
     */
    public function testCanCreateNewClientFromFormData(): void
    {
        $clientData = [
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
            'allowed_origin' => [],
            'post_logout_redirect_uri' => [],
            'backchannel_logout_uri' => null,
            'entity_identifier' => null,
            'client_registration_types' => null,
            'federation_jwks' => null,
            'jwks' => null,
            'jwks_uri' => null,
            'signed_jwks_uri' => null,
            'is_federated' => false,
        ];

        $this->clientFormMock
            ->expects($this->once())
            ->method('setAction')
            ->with($this->anything());
        $this->clientFormMock
            ->expects($this->once())
            ->method('isSuccess')
            ->willReturn(true);
        $this->clientFormMock
            ->expects($this->once())
            ->method('getValues')
            ->willReturn($clientData);

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->willReturn($this->clientFormMock);

        $this->clientEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($this->clientEntityMock);

        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('add')
            ->with($this->isInstanceOf(ClientEntity::class));

        $this->allowedOriginRepositoryMock
            ->expects($this->once())
            ->method('set')
            ->with($this->isType('string'), []);
        $this->sessionMessageServiceMock
            ->expects($this->once())
            ->method('addMessage')
            ->with('{oidc:client:added}');

        $this->assertInstanceOf(RedirectResponse::class, $this->mock()->__invoke());
    }

    /**
     * @throws \Exception
     */
    public function testCanSetOwnerInNewClient(): void
    {
        $this->authContextServiceMock->expects($this->once())->method('isSspAdmin')->willReturn(false);
        $this->authContextServiceMock->expects($this->once())
            ->method('getAuthUserId')->willReturn('ownerUsername');

        $this->clientFormMock
            ->expects($this->once())
            ->method('setAction')
            ->with($this->anything());
        $this->clientFormMock
            ->expects($this->once())
            ->method('isSuccess')
            ->willReturn(true);
        $this->clientFormMock
            ->expects($this->once())
            ->method('getValues')
            ->willReturn(
                [
                    'name' => 'name',
                    'description' => 'description',
                    'auth_source' => 'auth_source',
                    'redirect_uri' => ['http://localhost/redirect'],
                    'scopes' => ['openid'],
                    'is_enabled' => true,
                    'is_confidential' => false,
                    'owner' => 'wrongOwner',
                    'allowed_origin' => [],
                    'post_logout_redirect_uri' => [],
                    'backchannel_logout_uri' => null,
                    'entity_identifier' => null,
                    'client_registration_types' => null,
                    'federation_jwks' => null,
                    'jwks' => null,
                    'jwks_uri' => null,
                    'signed_jwks_uri' => null,
                    'is_federated' => false,
                ],
            );

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->willReturn($this->clientFormMock);

        $this->clientEntityMock->expects($this->once())
            ->method('getOwner')
            ->willReturn('ownerUsername');

        $this->clientEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($this->clientEntityMock);

        $this->clientRepositoryMock->expects($this->once())->method('add')
            ->with($this->callback(fn($client) => is_callable([$client, 'getOwner']) &&
                $client->getOwner() == 'ownerUsername'));

        $this->sessionMessageServiceMock
            ->expects($this->once())
            ->method('addMessage')
            ->with('{oidc:client:added}');

        $this->assertInstanceOf(RedirectResponse::class, $this->mock()->__invoke());
    }
}
