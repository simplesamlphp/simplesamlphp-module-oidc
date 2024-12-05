<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

#[CoversClass(PsrHttpBridge::class)]
class PsrHttpBridgeTest extends TestCase
{
    protected MockObject $httpFoundationFactoryMock;
    protected MockObject $serverRequestFactoryMock;
    protected MockObject $responseFactoryMock;
    protected MockObject $streamFactoryMock;
    protected MockObject $uploadedFileFactoryMock;

    protected function setUp(): void
    {
        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->serverRequestFactoryMock = $this->createMock(ServerRequestFactoryInterface::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->streamFactoryMock = $this->createMock(StreamFactoryInterface::class);
        $this->uploadedFileFactoryMock = $this->createMock(UploadedFileFactoryInterface::class);
    }

    protected function sut(
        ?HttpFoundationFactory $httpFoundationFactory = null,
        ?ServerRequestFactoryInterface $serverRequestFactory = null,
        ?ResponseFactoryInterface $responseFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        ?UploadedFileFactoryInterface $uploadedFileFactory = null,
    ): PsrHttpBridge {
        $httpFoundationFactory ??= $this->httpFoundationFactoryMock;
        $serverRequestFactory ??= $this->serverRequestFactoryMock;
        $responseFactory ??= $this->responseFactoryMock;
        $streamFactory ??= $this->streamFactoryMock;
        $uploadedFileFactory ??= $this->uploadedFileFactoryMock;

        return new PsrHttpBridge(
            $httpFoundationFactory,
            $serverRequestFactory,
            $responseFactory,
            $streamFactory,
            $uploadedFileFactory,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(PsrHttpBridge::class, $this->sut());
    }

    public function testCanGetProperties(): void
    {
        $sut = $this->sut();

        $this->assertInstanceOf(HttpFoundationFactory::class, $sut->getHttpFoundationFactory());
        $this->assertInstanceOf(ServerRequestFactoryInterface::class, $sut->getServerRequestFactory());
        $this->assertInstanceOf(ResponseFactoryInterface::class, $sut->getResponseFactory());
        $this->assertInstanceOf(StreamFactoryInterface::class, $sut->getStreamFactory());
        $this->assertInstanceOf(UploadedFileFactoryInterface::class, $sut->getUploadedFileFactory());
        $this->assertInstanceOf(PsrHttpFactory::class, $sut->getPsrHttpFactory());
    }
}
