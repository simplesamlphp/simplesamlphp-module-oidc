<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class ErrorResponder
{
    public function __construct(
        private readonly PsrHttpBridge $psrHttpBridge,
    ) {
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\Error
     */
    public function forException(Throwable $exception): Response
    {
        // We'll throw SSP Errors, so they are simply shown.
        if (is_a($exception, Error::class)) {
            throw $exception;
        }

        if (is_a($exception, OAuthServerException::class)) {
            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $exception->generateHttpResponse($this->psrHttpBridge->getResponseFactory()->createResponse()),
            );
        }

        return new JsonResponse(
            [
                'error' => [
                    'code' => 500,
                    'message' => $exception->getMessage(),
                ],
            ],
            500,
        );
    }
}
