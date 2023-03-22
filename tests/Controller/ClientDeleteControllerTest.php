<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Controller\ClientDeleteController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\ClientDeleteController
 */
class ClientDeleteControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $templateFactoryMock;
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

    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->sessionMessageServiceMock = $this->createMock(SessionMessagesService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->uriStub = $this->createStub(UriInterface::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->templateStub = $this->createStub(Template::class);
    }

    protected function getStubbedInstance(): ClientDeleteController
    {
        return new ClientDeleteController(
            $this->clientRepositoryMock,
            $this->templateFactoryMock,
            $this->sessionMessageServiceMock,
            $this->authContextServiceMock
        );
    }

    public function testCanInstantiate(): void
    {
        $controller = $this->getStubbedInstance();
        $this->assertInstanceOf(ClientDeleteController::class, $controller);
    }

    public function testItAsksConfirmationBeforeDeletingClient(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')->willReturn([]);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('get');
        $this->clientRepositoryMock->expects($this->once())->method('findById')->with('clientid')
            ->willReturn($this->clientEntityMock);
        $this->templateFactoryMock->expects($this->once())->method('render')
            ->with('oidc:clients/delete.twig', ['client' => $this->clientEntityMock])
            ->willReturn($this->templateStub);

        $controller = $this->getStubbedInstance();

        $this->assertInstanceOf(Template::class, $controller->__invoke($this->serverRequestMock));
    }

    public function testThrowsIfIdNotFoundInDeleteAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')->willReturn([]);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    public function testThrowsIfSecretNotFoundInDeleteAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')->willReturn([]);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    public function testThrowsIfSecretIsInvalidInDeleteAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')
            ->willReturn(['secret' => 'invalidsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('validsecret');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    public function testItDeletesClient(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')
            ->willReturn(['secret' => 'validsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('validsecret');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);
        $this->clientRepositoryMock->expects($this->once())->method('delete')
            ->with($this->clientEntityMock, null);
        $this->sessionMessageServiceMock->expects($this->once())->method('addMessage')
            ->with('{oidc:client:removed}');

        $this->assertInstanceOf(
            RedirectResponse::class,
            ($this->getStubbedInstance())->__invoke($this->serverRequestMock)
        );
    }

    public function testItDeletesClientWithOwner(): void
    {
        $this->authContextServiceMock->expects($this->exactly(2))->method('isSspAdmin')->willReturn(false);
        $this->authContextServiceMock->expects($this->exactly(2))->method('getAuthUserId')->willReturn('theOwner');
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getParsedBody')
            ->willReturn(['secret' => 'validsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');
        $this->clientEntityMock->expects($this->once())->method('getSecret')->willReturn('validsecret');
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->willReturn($this->clientEntityMock);
        $this->clientRepositoryMock->expects($this->once())->method('delete')
            ->with($this->clientEntityMock, 'theOwner');
        $this->sessionMessageServiceMock->expects($this->once())->method('addMessage')
            ->with('{oidc:client:removed}');

        $this->assertInstanceOf(
            RedirectResponse::class,
            ($this->getStubbedInstance())->__invoke($this->serverRequestMock)
        );
    }
}
