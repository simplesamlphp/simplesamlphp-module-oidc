<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Helpers;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

class HttpTest extends TestCase
{
    protected MockObject $serverRequestMock;

    protected function setUp(): void
    {
        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
    }

    protected function sut(): Http
    {
        return new Http();
    }

    public function testCanGetAllRequestParams(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['a' => 'b']);

        $this->serverRequestMock->expects($this->once())->method('getParsedBody')
            ->willReturn(['c' => 'd']);

        $this->assertSame(
            ['a' => 'b', 'c' => 'd'],
            $this->sut()->getAllRequestParams($this->serverRequestMock),
        );
    }

    public function testCanGetAllRequestParamsBasedOnAllowedMethodsForGet(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')
            ->willReturn(HttpMethodsEnum::GET->value);

        $this->serverRequestMock->expects($this->once())->method('getQueryParams')
            ->willReturn(['a' => 'b']);

        $this->assertSame(
            ['a' => 'b'],
            $this->sut()->getAllRequestParamsBasedOnAllowedMethods(
                $this->serverRequestMock,
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            ),
        );
    }

    public function testCanGetAllRequestParamsBasedOnAllowedMethodsForPost(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')
            ->willReturn(HttpMethodsEnum::POST->value);

        $this->serverRequestMock->expects($this->once())->method('getParsedBody')
            ->willReturn(['c' => 'd']);

        $this->assertSame(
            ['c' => 'd'],
            $this->sut()->getAllRequestParamsBasedOnAllowedMethods(
                $this->serverRequestMock,
                [HttpMethodsEnum::GET, HttpMethodsEnum::POST],
            ),
        );
    }

    public function testGerAllRequestParamsBasedOnAllowedMethodsReturnsNullForNonAllowedMethod(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')
            ->willReturn(HttpMethodsEnum::POST->value);

        $this->assertNull(
            $this->sut()->getAllRequestParamsBasedOnAllowedMethods(
                $this->serverRequestMock,
                [HttpMethodsEnum::GET],
            ),
        );
    }
}
