<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\ClientResetSecretController;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\ClientResetSecretController
 *
 * @backupGlobals enabled
 */
class ClientResetSecretControllerTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientRepositoryMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $sessionMessagesServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $authContextServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $clientEntityMock;

    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
    }

    public static function setUpBeforeClass(): void
    {
        // To make lib/SimpleSAML/Utils/HTTP::getSelfURL() work...
        global $_SERVER;
        $_SERVER['REQUEST_URI'] = '';
    }

    protected function prepareStubbedInstance(): ClientResetSecretController
    {
        return new ClientResetSecretController(
            $this->clientRepositoryMock,
            $this->sessionMessagesServiceMock,
            $this->authContextServiceMock
        );
    }

    public function testCanInstantiate(): void
    {
        $this->assertInstanceOf(
            ClientResetSecretController::class,
            $this->prepareStubbedInstance()
        );
    }

    public function testItThrowsIdNotFoundExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock->method('getQueryParams')->willReturn([]);
        $this->expectException(BadRequest::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    public function testItThrowsClientNotFoundExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock->method('getQueryParams')->willReturn(['client_id' => 'clientid']);
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn(null);

        $this->expectException(NotFound::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    public function testThrowsSecretNotFoundExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn($this->clientEntityMock);

        $this->expectException(BadRequest::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    public function testThrowsSecretInvalidExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['secret' => 'invalidsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');

        $this->clientEntityMock->method('getSecret')->willReturn('validsecret');
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn($this->clientEntityMock);

        $this->expectException(BadRequest::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    public function testItResetSecretsClient(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['secret' => 'validsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('post');

        $this->clientEntityMock->method('getIdentifier')->willReturn('clientid');
        $this->clientEntityMock->method('getSecret')->willReturn('validsecret');
        $this->clientEntityMock->expects($this->once())->method('restoreSecret');

        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn($this->clientEntityMock);
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('update')
            ->with($this->clientEntityMock);

        $this->sessionMessagesServiceMock
            ->expects($this->once())
            ->method('addMessage')
            ->with('{oidc:client:secret_updated}');

        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    public function testItSendBackToShowClientIfNotPostMethodInResetAction(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getParsedBody')
            ->willReturn(['secret' => 'validsecret']);
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('get');

        $this->clientEntityMock->method('getIdentifier')->willReturn('clientid');

        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn($this->clientEntityMock);

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->prepareStubbedInstance()->__invoke($this->serverRequestMock)
        );
    }
}
