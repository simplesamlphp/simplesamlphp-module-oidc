<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\ClientCreateController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\ClientCreateController
 */
class ClientCreateControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $allowedOriginRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $templateFactoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $formFactoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $sessionMessageServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $authContextServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientFormMock;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $serverRequestStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $templateStub;

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
    }

    public function testCanInstantiate(): void
    {
        $controller = $this->getStubbedInstance();
        $this->assertInstanceOf(ClientCreateController::class, $controller);
    }

    protected function getStubbedInstance(): ClientCreateController
    {
        return new ClientCreateController(
            $this->clientRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->templateFactoryMock,
            $this->formFactoryMock,
            $this->sessionMessageServiceMock,
            $this->authContextServiceMock
        );
    }

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
            ->method('render')
            ->with('oidc:clients/new.twig', [
                'form' => $this->clientFormMock,
                'regexUri' => ClientForm::REGEX_URI,
                'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
                'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
            ])
            ->willReturn($this->templateStub);

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->with($this->equalTo(ClientForm::class))
            ->willReturn($this->clientFormMock);

        $controller = $this->getStubbedInstance();
        $this->assertSame($this->templateStub, $controller->__invoke($this->serverRequestStub));
    }

    public function testCanCreateNewClientFromFormData(): void
    {
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
                     'allowed_origin' => [],
                     'post_logout_redirect_uri' => [],
                     'backchannel_logout_uri' => null,
                 ]
            );

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->willReturn($this->clientFormMock);

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

        $controller = $this->getStubbedInstance();
        $this->assertInstanceOf(RedirectResponse::class, $controller->__invoke($this->serverRequestStub));
    }

    public function testCanSetOwnerInNewClient(): void
    {
        $this->authContextServiceMock->expects($this->once())->method('isSspAdmin')->willReturn(false);
        $this->authContextServiceMock->method('getAuthUserId')->willReturn('ownerUsername');

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
                ]
            );

        $this->formFactoryMock
            ->expects($this->once())
            ->method('build')
            ->willReturn($this->clientFormMock);

        $this->clientRepositoryMock->expects($this->once())->method('add')
            ->with($this->callback(function ($client) {
                return is_callable([$client, 'getOwner']) &&
                    $client->getOwner() == 'ownerUsername';
            }));

        $this->sessionMessageServiceMock
            ->expects($this->once())
            ->method('addMessage')
            ->with('{oidc:client:added}');

        $controller = $this->getStubbedInstance();
        $this->assertInstanceOf(RedirectResponse::class, $controller->__invoke($this->serverRequestStub));
    }
}
