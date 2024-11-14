<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controller\Client;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Controller\Client\ShowController;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Client\ShowController
 *
 * @backupGlobals enabled
 */
class ShowControllerTest extends TestCase
{
    protected MockObject $clientRepositoryMock;
    protected MockObject $allowedOriginRepositoryMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $authContextServiceMock;
    protected MockObject $clientEntityMock;
    protected MockObject $serverRequestMock;
    protected MockObject $templateMock;

    /**
     * @throws \SimpleSAML\Error\Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->allowedOriginRepositoryMock = $this->createMock(AllowedOriginRepository::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->templateMock = $this->createMock(Template::class);
    }

    protected function getStubbedInstance(): ShowController
    {
        return new ShowController(
            $this->clientRepositoryMock,
            $this->allowedOriginRepositoryMock,
            $this->templateFactoryMock,
            $this->authContextServiceMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ShowController::class,
            $this->getStubbedInstance(),
        );
    }

    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItShowsClientDescription(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->clientEntityMock->expects($this->once())->method('getIdentifier')->willReturn('clientid');
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->willReturn($this->clientEntityMock);
        $this->allowedOriginRepositoryMock
            ->expects($this->once())
            ->method('get')
            ->with('clientid')
            ->willReturn([]);
        $this->templateFactoryMock
            ->expects($this->once())
            ->method('build')
            ->with(
                'oidc:clients/show.twig',
                [
                    'client' => $this->clientEntityMock,
                    'allowedOrigins' => [],
                ],
            )->willReturn($this->templateMock);

        $this->assertSame(
            $this->templateMock,
            $this->getStubbedInstance()->__invoke($this->serverRequestMock),
        );
    }

    /**
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Error\NotFound
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItThrowsIdNotFoundException(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')->willReturn([]);

        $this->expectException(BadRequest::class);
        $this->getStubbedInstance()->__invoke($this->serverRequestMock);
    }

    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testItThrowsClientNotFoundException(): void
    {
        $this->serverRequestMock
            ->expects($this->once())
            ->method('getQueryParams')
            ->willReturn(['client_id' => 'clientid']);
        $this->clientRepositoryMock
            ->expects($this->once())
            ->method('findById')
            ->with('clientid')
            ->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->getStubbedInstance()->__invoke($this->serverRequestMock);
    }
}
