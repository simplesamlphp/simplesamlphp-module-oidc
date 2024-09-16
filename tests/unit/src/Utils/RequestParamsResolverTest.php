<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\RequestObjectFactory;
use SimpleSAML\OpenID\Core\RequestObject;
use SimpleSAML\OpenID\Federation;

#[CoversClass(RequestParamsResolver::class)]
class RequestParamsResolverTest extends TestCase
{
    protected MockObject $helpersMock;
    protected MockObject $httpHelperMock;
    protected MockObject $coreMock;
    protected MockObject $requestMock;
    protected MockObject $requestObjectMock;
    protected MockObject $requestObjectFactoryMock;
    protected MockObject $federationMock;

    protected array $queryParams = [
        'a' => 'b',
    ];

    protected array $bodyParams = [
        'c' => 'd',
    ];

    protected array $requestObjectParams = [
        'e' => 'f',
    ];

    protected function setUp(): void
    {
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->httpHelperMock = $this->createMock(Helpers\Http::class);
        $this->httpHelperMock->method('getAllRequestParams')
            ->willReturn(array_merge($this->queryParams, $this->bodyParams));
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('http')->willReturn($this->httpHelperMock);
        $this->requestObjectMock = $this->createMock(RequestObject::class);
        $this->requestObjectMock->method('getPayload')->willReturn($this->requestObjectParams);
        $this->requestObjectFactoryMock = $this->createMock(RequestObjectFactory::class);
        $this->requestObjectFactoryMock->method('fromToken')->willReturn($this->requestObjectMock);
        $this->coreMock = $this->createMock(Core::class);
        $this->coreMock->method('requestObjectFactory')->willReturn($this->requestObjectFactoryMock);
        $this->federationMock = $this->createMock(Federation::class);
    }

    protected function mock(
        MockObject $helpersMock = null,
        MockObject $coreMock = null,
        MockObject $federationMock = null,
    ): RequestParamsResolver {
        $helpersMock ??= $this->helpersMock;
        $coreMock ??= $this->coreMock;
        $federationMock ??= $this->federationMock;

        return new RequestParamsResolver($helpersMock, $coreMock, $federationMock);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestParamsResolver::class, $this->mock());
    }

    public function testCanGetAllFromRequest(): void
    {
        $this->assertSame(
            array_merge($this->queryParams, $this->bodyParams),
            $this->mock()->getAllFromRequest($this->requestMock),
        );
    }

    public function testCanGetAllFromRequestBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);

        $this->assertSame(
            $this->queryParams,
            $this->mock()->getAllFromRequestBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }

    public function testCanGetAllWithNoRequestObject(): void
    {
        $this->assertSame(
            array_merge($this->queryParams, $this->bodyParams),
            $this->mock()->getAll($this->requestMock),
        );
    }

    public function testCanGetAllWithRequestObject(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];

        $httpHelperMock = $this->createMock(Helpers\Http::class);
        $httpHelperMock->method('getAllRequestParams')->willReturn($queryParams);
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('http')->willReturn($httpHelperMock);
        $this->requestObjectMock->expects($this->once())->method('getPayload');

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $this->mock($helpersMock)->getAll($this->requestMock),
        );
    }

    public function testCanGetAllBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods');
        $this->requestObjectMock->expects($this->never())->method('getPayload');

        $this->mock()->getAllBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::GET]);
    }

    public function testCanGetBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getBasedOnAllowedMethods('a', $this->requestMock),
        );
    }

    public function testCanGetAsStringBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getAsStringBasedOnAllowedMethods('a', $this->requestMock),
        );

        $this->assertNull($this->mock()->getAsStringBasedOnAllowedMethods('b', $this->requestMock));
    }

    public function testCanGetFromRequestBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getFromRequestBasedOnAllowedMethods('a', $this->requestMock),
        );
    }
}
