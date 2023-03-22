<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use Psr\Http\Message\UriInterface;
use SimpleSAML\Module\oidc\Controller\ClientIndexController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Entity\ClientEntity;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Form\ClientForm;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\XHTML\Template;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\ClientIndexController
 */
class ClientIndexControllerTest extends TestCase
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
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $templateStub;

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

    protected function getStubbedInstance(): ClientIndexController
    {
        return new ClientIndexController(
            $this->clientRepositoryMock,
            $this->templateFactoryMock,
            $this->authContextServiceMock
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(ClientIndexController::class, $this->getStubbedInstance());
    }

    public function testItShowsClientIndex(): void
    {
        $this->clientRepositoryMock->expects($this->once())->method('findPaginated')
            ->with(1, '', null)
            ->willReturn(
                [
                    'items' => [],
                    'numPages' => 1,
                    'currentPage' => 1
                ]
            );

        $this->templateFactoryMock->expects($this->once())->method('render')->with(
            'oidc:clients/index.twig',
            [
                'clients' => [],
                'numPages' => 1,
                'currentPage' => 1,
                'query' => '',
            ]
        )->willReturn($this->templateStub);

        $this->assertSame($this->templateStub, ($this->getStubbedInstance())->__invoke($this->serverRequestMock));
    }
}
