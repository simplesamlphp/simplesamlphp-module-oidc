<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Federation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\Federation\SubordinateListingsController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(SubordinateListingsController::class)]
final class SubordinateListingsControllerTest extends TestCase
{
    private MockObject $moduleConfigMock;
    private MockObject $clientRepositoryMock;
    private MockObject $routesMock;

    private bool $isFederationEnabled;
    private MockObject $requestMock;
    private MockObject $requestQueryMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->routesMock = $this->createMock(Routes::class);

        $this->isFederationEnabled = true;

        $this->requestMock = $this->createMock(Request::class);
        $this->requestQueryMock = $this->createMock(ParameterBag::class);
        $this->requestMock->query = $this->requestQueryMock;
    }

    public function sut(
        ?ModuleConfig $moduleConfig = null,
        ?ClientRepository $clientRepository = null,
        ?Routes $routes = null,
        ?bool $federationEnabled = null,
    ): SubordinateListingsController {
        $federationEnabled = $federationEnabled ?? $this->isFederationEnabled;
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn($federationEnabled);

        $moduleConfig = $moduleConfig ?? $this->moduleConfigMock;
        $clientRepository = $clientRepository ?? $this->clientRepositoryMock;
        $routes = $routes ?? $this->routesMock;

        return new SubordinateListingsController(
            $moduleConfig,
            $clientRepository,
            $routes,
        );
    }

    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(SubordinateListingsController::class, $this->sut());
    }

    public function testThrowsIfFederationNotEnabled(): void
    {
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('refused');

        $this->sut(federationEnabled: false);
    }

    public function testCanListFederatedEntities(): void
    {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getEntityIdentifier')->willReturn('entity-id');

        $federatedEntities = [
            $client,
        ];

        $this->clientRepositoryMock->expects($this->once())->method('findAllFederated')
            ->willReturn($federatedEntities);

        $this->routesMock->expects($this->once())->method('newJsonResponse')
            ->with([
                $client->getEntityIdentifier(),
            ]);

        $this->sut()->list($this->requestMock);
    }

    public function testListReturnsErrorOnUnsuportedQueryParameter(): void
    {
        $this->requestQueryMock->method('all')->willReturn([
            ParamsEnum::EntityType->value => 'something',
        ]);

        $this->routesMock->expects($this->once())->method('newJsonErrorResponse')
            ->with(ErrorsEnum::UnsupportedParameter->value);

        $this->sut()->list($this->requestMock);
    }
}
