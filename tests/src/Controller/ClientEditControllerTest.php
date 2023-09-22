<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Controller\ClientEditController;
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
 * @covers \SimpleSAML\Module\oidc\Controller\ClientEditController
 */
class ClientEditControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $moduleConfigMock;
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
    protected $serverRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $uriStub;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $authContextServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientEntityMock;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $templateStub;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientFormMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->sessionMessageServiceMock = $this->createMock(SessionMessagesService::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->uriStub = $this->createStub(UriInterface::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->templateStub = $this->createStub(Template::class);
        $this->clientFormMock = $this->createMock(ClientForm::class);

        $this->moduleConfigMock->method('getOpenIdConnectModuleURL')->willReturn('url');
        $this->uriStub->method('getPath')->willReturn('/');
        $this->serverRequestMock->method('getUri')->willReturn($this->uriStub);
        $this->serverRequestMock->method('withQueryParams')->willReturn($this->serverRequestMock);
    }

    protected function getStubbedInstance(): ClientEditController
    {
        return new ClientEditController(
            $this->clientRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->templateFactoryMock,
            $this->formFactoryMock,
            $this->sessionMessageServiceMock,
            $this->authContextServiceMock
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(ClientEditController::class, $this->getStubbedInstance());
    }

    public function testItShowsEditClientForm(): void
    {
        $this->authContextServiceMock->method('isSspAdmin')->willReturn(true);

        $data = [
            'id' => 'clientid',
            'secret' => 'validsecret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'allowed_origin' => [],
            'post_logout_redirect_uri' => [],
            'backchannel_logout_uri' => null,
        ];

        $this->clientEntityMock->expects($this->atLeastOnce())->method('getIdentifier')->willReturn('clientid');
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->clientEntityMock->expects($this->once())->method('toArray')->willReturn($data);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);
        $this->allowedOriginRepositoryMock->expects($this->once())->method('get')->with('clientid')
            ->willReturn([]);
        $this->clientFormMock->expects($this->once())->method('setAction');
        $this->clientFormMock->expects($this->once())->method('setDefaults')->with($data);
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(false);
        $this->formFactoryMock->expects($this->once())->method('build')->willReturn($this->clientFormMock);
        $this->templateFactoryMock->expects($this->once())->method('render')->with(
            'oidc:clients/edit.twig',
            [
                'form' => $this->clientFormMock,
                'regexUri' => ClientForm::REGEX_URI,
                'regexAllowedOriginUrl' => ClientForm::REGEX_ALLOWED_ORIGIN_URL,
                'regexHttpUri' => ClientForm::REGEX_HTTP_URI,
            ]
        )->willReturn($this->templateStub);

        $this->assertSame(
            ($this->getStubbedInstance())->__invoke($this->serverRequestMock),
            $this->templateStub
        );
    }

    public function testItUpdatesClientFromEditClientFormData(): void
    {
        $this->authContextServiceMock->method('isSspAdmin')->willReturn(true);

        $data = [
            'id' => 'clientid',
            'secret' => 'validsecret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
            'owner' => 'existingOwner',
            'allowed_origin' => [],
            'post_logout_redirect_uri' => [],
            'backchannel_logout_uri' => null,
        ];

        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);

        $this->clientEntityMock->expects($this->atLeastOnce())->method('getIdentifier')->willReturn('clientid');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('validsecret');
        $this->clientEntityMock->expects($this->once())->method('getOwner')->willReturn('existingOwner');
        $this->clientEntityMock->expects($this->once())->method('toArray')->willReturn($data);

        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);

        $this->allowedOriginRepositoryMock->expects($this->once())->method('get')->with('clientid')
            ->willReturn([]);

        $this->clientFormMock->expects($this->once())->method('setAction');
        $this->clientFormMock->expects($this->once())->method('setDefaults')->with($data);
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->expects($this->once())->method('getValues')->willReturn(
            [
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => ['http://localhost/redirect'],
                'scopes' => ['openid'],
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'existingOwner',
                'allowed_origin' => [],
                'post_logout_redirect_uri' => [],
                'backchannel_logout_uri' => null,
            ]
        );

        $this->formFactoryMock->expects($this->once())->method('build')->willReturn($this->clientFormMock);

        $this->clientRepositoryMock->expects($this->once())->method('update')->with(
            ClientEntity::fromData(
                'clientid',
                'validsecret',
                'name',
                'description',
                ['http://localhost/redirect'],
                ['openid'],
                true,
                false,
                'auth_source',
                'existingOwner',
                []
            ),
            null
        );

        $this->allowedOriginRepositoryMock->expects($this->once())->method('set')->with('clientid', []);
        $this->sessionMessageServiceMock->expects($this->once())->method('addMessage')
            ->with('{oidc:client:updated}');

        $this->assertInstanceOf(
            RedirectResponse::class,
            ($this->getStubbedInstance())->__invoke($this->serverRequestMock)
        );
    }

    public function testItSendsOwnerArgToRepoOnUpdate(): void
    {
        $this->authContextServiceMock->expects($this->atLeastOnce())->method('isSspAdmin')->willReturn(false);
        $this->authContextServiceMock->method('getAuthUserId')->willReturn('authedUserId');
        $data = [
            'id' => 'clientid',
            'secret' => 'validsecret',
            'name' => 'name',
            'description' => 'description',
            'auth_source' => 'auth_source',
            'redirect_uri' => ['http://localhost/redirect'],
            'scopes' => ['openid'],
            'is_enabled' => true,
            'is_confidential' => false,
            'owner' => 'existingOwner',
            'allowed_origin' => [],
            'post_logout_redirect_uri' => [],
            'backchannel_logout_uri' => null,
        ];

        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);

        $this->clientEntityMock->expects($this->atLeastOnce())->method('getIdentifier')->willReturn('clientid');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('validsecret');
        $this->clientEntityMock->expects($this->once())->method('getOwner')->willReturn('existingOwner');
        $this->clientEntityMock->expects($this->once())->method('toArray')->willReturn($data);

        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientid', 'authedUserId')->willReturn($this->clientEntityMock);

        $this->allowedOriginRepositoryMock->expects($this->once())->method('get')->with('clientid')
            ->willReturn([]);

        $this->clientFormMock->expects($this->once())->method('setAction');
        $this->clientFormMock->expects($this->once())->method('setDefaults')->with($data);
        $this->clientFormMock->expects($this->once())->method('isSuccess')->willReturn(true);
        $this->clientFormMock->expects($this->once())->method('getValues')->willReturn(
            [
                'name' => 'name',
                'description' => 'description',
                'auth_source' => 'auth_source',
                'redirect_uri' => ['http://localhost/redirect'],
                'scopes' => ['openid'],
                'is_enabled' => true,
                'is_confidential' => false,
                'owner' => 'existingOwner',
                'allowed_origin' => [],
                'post_logout_redirect_uri' => [],
                'backchannel_logout_uri' => null,
            ]
        );

        $this->formFactoryMock->expects($this->once())->method('build')->willReturn($this->clientFormMock);

        $this->clientRepositoryMock->expects($this->once())->method('update')->with(
            ClientEntity::fromData(
                'clientid',
                'validsecret',
                'name',
                'description',
                ['http://localhost/redirect'],
                ['openid'],
                true,
                false,
                'auth_source',
                'existingOwner',
                [],
                null
            ),
            'authedUserId'
        );

        $this->allowedOriginRepositoryMock->expects($this->once())->method('get')->with('clientid')
            ->willReturn([]);
        $this->allowedOriginRepositoryMock->expects($this->once())->method('set')->with('clientid', []);
        $this->sessionMessageServiceMock->expects($this->once())->method('addMessage')
            ->with('{oidc:client:updated}');

        $this->assertInstanceOf(
            RedirectResponse::class,
            ($this->getStubbedInstance())->__invoke($this->serverRequestMock)
        );
    }

    public function testThrowsIdNotFoundExceptionInEditAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')->willReturn([]);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    public function testThrowsClientNotFoundExceptionInEditAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->clientRepositoryMock->expects($this->once())->method('findById')->willReturn(null);

        $this->expectException(\Exception::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }
}
