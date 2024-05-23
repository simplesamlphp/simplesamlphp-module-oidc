<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Controller\Client;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Module\oidc\Controller\Client\IndexController;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\Client\IndexController
 */
class IndexControllerTest extends TestCase
{
    protected MockObject $clientRepositoryMock;
    protected MockObject $templateFactoryMock;
    protected MockObject $serverRequestMock;
    protected Stub $uriStub;
    protected MockObject $authContextServiceMock;
    protected Stub $templateStub;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->authContextServiceMock = $this->createMock(AuthContextService::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->uriStub = $this->createStub(UriInterface::class);

        $this->templateStub = $this->createStub(Template::class);

        $this->authContextServiceMock->method('isSspAdmin')->willReturn(true);
        $this->uriStub->method('getPath')->willReturn('/');
        $this->serverRequestMock->method('getUri')->willReturn($this->uriStub);
        $this->serverRequestMock->method('getQueryParams')->willReturn(['page' => 1]);
    }

    protected function getStubbedInstance(): IndexController
    {
        return new IndexController(
            $this->clientRepositoryMock,
            $this->templateFactoryMock,
            $this->authContextServiceMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(IndexController::class, $this->getStubbedInstance());
    }

    /**
     * @throws \SimpleSAML\Error\Exception
     */
    public function testItShowsClientIndex(): void
    {
        $this->clientRepositoryMock->expects($this->once())->method('findPaginated')
            ->with(1, '', null)
            ->willReturn(
                [
                    'items' => [],
                    'numPages' => 1,
                    'currentPage' => 1,
                ],
            );

        $this->templateFactoryMock->expects($this->once())->method('render')->with(
            'oidc:clients/index.twig',
            [
                'clients' => [],
                'numPages' => 1,
                'currentPage' => 1,
                'query' => '',
            ],
        )->willReturn($this->templateStub);

        $this->assertSame($this->templateStub, ($this->getStubbedInstance())->__invoke($this->serverRequestMock));
    }
}
