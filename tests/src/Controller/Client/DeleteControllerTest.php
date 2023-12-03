<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller\Client;

use JsonException;
use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Client\DeleteController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Client\DeleteController
 */
class DeleteControllerTest extends TestCase
{
    protected MockObject $clientRepositoryMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $sessionMessageServiceMock;
    protected MockObject $serverRequestMock;
    protected Stub $uriStub;
    protected MockObject $authContextServiceMock;
    protected MockObject $clientEntityMock;
    protected Stub $templateStub;

    /**
     * @throws Exception
     */
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

    protected function getStubbedInstance(): \SimpleSAML\Module\oidc\Controller\Client\DeleteController
    {
        return new DeleteController(
            $this->clientRepositoryMock,
            $this->templateFactoryMock,
            $this->sessionMessageServiceMock,
            $this->authContextServiceMock
        );
    }

    public function testCanInstantiate(): void
    {
        $controller = $this->getStubbedInstance();
        $this->assertInstanceOf(\SimpleSAML\Module\oidc\Controller\Client\DeleteController::class, $controller);
    }

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
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

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
    public function testThrowsIfIdNotFoundInDeleteAction(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')->willReturn([]);

        $this->expectException(BadRequest::class);

        ($this->getStubbedInstance())->__invoke($this->serverRequestMock);
    }

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
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

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
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

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
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

    /**
     * @throws ConfigurationError|BadRequest|NotFound|\SimpleSAML\Error\Exception|OidcServerException|JsonException
     */
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
