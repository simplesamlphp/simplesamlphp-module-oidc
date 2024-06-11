<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class PsrHttpBridge
{
    private PsrHttpFactory $psrHttpFactory;

    public function __construct(
        private readonly HttpFoundationFactory $httpFoundationFactory,
        private readonly ServerRequestFactoryInterface $serverRequestFactory,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly UploadedFileFactoryInterface $uploadedFileFactory,
    ) {
        $this->psrHttpFactory = new PsrHttpFactory(
            $this->serverRequestFactory,
            $this->streamFactory,
            $this->uploadedFileFactory,
            $this->responseFactory,
        );
    }

    public function getHttpFoundationFactory(): HttpFoundationFactory
    {
        return $this->httpFoundationFactory;
    }

    public function getServerRequestFactory(): ServerRequestFactoryInterface
    {
        return $this->serverRequestFactory;
    }

    public function getResponseFactory(): ResponseFactoryInterface
    {
        return $this->responseFactory;
    }

    public function getStreamFactory(): StreamFactoryInterface
    {
        return $this->streamFactory;
    }

    public function getUploadedFileFactory(): UploadedFileFactoryInterface
    {
        return $this->uploadedFileFactory;
    }

    public function getPsrHttpFactory(): PsrHttpFactory
    {
        return $this->psrHttpFactory;
    }
}
