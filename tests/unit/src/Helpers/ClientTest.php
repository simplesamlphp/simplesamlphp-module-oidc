<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;

#[CoversClass(Client::class)]
class ClientTest extends TestCase
{
    protected MockObject $httpMock;
    protected MockObject $requestMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $clientEntityMock;

    protected function sut(
        ?Http $http = null,
    ): Client {
        $http ??= $this->httpMock;

        return new Client($http);
    }

    protected function setUp(): void
    {
        $this->httpMock = $this->createMock(Http::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
    }

    public function testCanGetFromRequest(): void
    {
        $this->httpMock->expects($this->once())->method('getAllRequestParams')
            ->willReturn(['client_id' => 'clientId']);

        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientId')
            ->willReturn($this->clientEntityMock);

        $this->assertInstanceOf(
            ClientEntity::class,
            $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock),
        );
    }

    public function testGetFromRequestThrowsIfNoClientId(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client ID');

        $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock);
    }

    public function testGetFromRequestThrowsIfClientNotFound(): void
    {
        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Client not found');

        $this->httpMock->expects($this->once())->method('getAllRequestParams')
            ->willReturn(['client_id' => 'clientId']);
        $this->clientRepositoryMock->expects($this->once())->method('findById')
            ->with('clientId')
            ->willReturn(null);

        $this->sut()->getFromRequest($this->requestMock, $this->clientRepositoryMock);
    }
}
