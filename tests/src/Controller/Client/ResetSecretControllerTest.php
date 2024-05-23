<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller\Client;

use Laminas\Diactoros\Response\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\NotFound;
use SimpleSAML\Module\oidc\Controller\Client\ResetSecretController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Client\ResetSecretController
 *
 * @backupGlobals enabled
 */
class ResetSecretControllerTest extends TestCase
{
    protected MockObject $clientRepositoryMock;
    protected MockObject $sessionMessagesServiceMock;
    protected MockObject $authContextServiceMock;
    protected MockObject $serverRequestMock;
    protected MockObject $clientEntityMock;

    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
    }

    protected function prepareStubbedInstance(): \SimpleSAML\Module\oidc\Controller\Client\ResetSecretController
    {
        return new ResetSecretController(
            $this->clientRepositoryMock,
            $this->sessionMessagesServiceMock,
            $this->authContextServiceMock
        );
    }

    public function testCanInstantiate(): void
    {
        $this->assertInstanceOf(
            \SimpleSAML\Module\oidc\Controller\Client\ResetSecretController::class,
            $this->prepareStubbedInstance()
        );
    }

    /**
     * @throws Exception
     * @throws NotFound
     */
    public function testItThrowsIdNotFoundExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock->method('getQueryParams')->willReturn([]);
        $this->expectException(BadRequest::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    /**
     * @throws BadRequest
     * @throws Exception
     */
    public function testItThrowsClientNotFoundExceptionInResetSecretAction(): void
    {
        $this->serverRequestMock->method('getQueryParams')->willReturn(['client_id' => 'clientid']);
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->prepareStubbedInstance()->__invoke($this->serverRequestMock);
    }

    /**
     * @throws Exception
     * @throws NotFound
     */
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

    /**
     * @throws Exception
     * @throws NotFound
     */
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

    /**
     * @throws BadRequest
     * @throws Exception
     * @throws NotFound
     */
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

    /**
     * @throws BadRequest
     * @throws Exception
     * @throws NotFound
     */
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
