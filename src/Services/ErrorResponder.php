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

    /**
     * Create a JSON error response (as specified for the token endpoint),
     * regardless of any redirect URI contained in the exception. This is
     * appropriate for endpoints which must not redirect on errors, like
     * the Pushed Authorization Request endpoint.
     */
    public function forExceptionJson(OAuthServerException $exception): JsonResponse
    {
        $body = [
            'error' => $exception->getErrorType(),
            'error_description' => $exception->getMessage(),
        ];

        if (($hint = $exception->getHint()) !== null) {
            $body['hint'] = $hint;
        }

        return new JsonResponse(
            $body,
            $exception->getHttpStatusCode(),
            ['Cache-Control' => 'no-cache, no-store'],
        );
    }
}
