<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller\Client;

use Exception;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Client\EditController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\ClientForm;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Client\EditController
 */
class EditControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $formFactoryMock;
    protected MockObject $sessionMessageServiceMock;
    protected MockObject $serverRequestMock;
    protected Stub $uriStub;
    protected MockObject $authContextServiceMock;
    protected MockObject $clientEntityMock;
    protected Stub $templateStub;
    protected MockObject $clientFormMock;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        // The REQUEST_URI is required either to create the session or to get the selfUrl
        $_SERVER['REQUEST_URI'] = '/';

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

    protected function getStubbedInstance(): EditController
    {
        return new EditController(
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
        $this->assertInstanceOf(
            EditController::class,
            $this->getStubbedInstance()
        );
    }

    /**
     * @throws BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws NotFound
     */
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

    /**
     * @throws BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws NotFound
     */
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

    /**
     * @throws BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws NotFound
     */
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

    /**
     * @throws \SimpleSAML\Error\Exception
     * @throws NotFound
     */
    public function testThrowsIdNotFoundExceptionInEditAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')->willReturn([]);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    /**
     * @throws BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws NotFound
     */
    public function testThrowsClientNotFoundExceptionInEditAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->clientRepositoryMock->expects($this->once())->method('findById')->willReturn(null);

        $this->expectException(Exception::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }
}
