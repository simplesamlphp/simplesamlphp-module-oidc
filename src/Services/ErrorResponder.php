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
        private readonly LoggerService $loggerService,
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
            $this->logOAuthServerException($exception);

            return $this->psrHttpBridge->getHttpFoundationFactory()->createResponse(
                $exception->generateHttpResponse($this->psrHttpBridge->getResponseFactory()->createResponse()),
            );
        }

        $this->logUnexpectedException($exception);

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
        $this->logOAuthServerException($exception);

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

    /**
     * Log an OAuth error that is about to be returned to the client. This is the single place every endpoint's
     * error response passes through, so it ensures the descriptive error type, description and hint (which the
     * client otherwise sees but the server log does not) end up in the log, without requiring debug logging.
     * The level reflects who is at fault: 5xx are server faults, 401/403 are security-relevant denials, and the
     * remaining 4xx are ordinary invalid-request problems.
     */
    private function logOAuthServerException(OAuthServerException $exception): void
    {
        $httpStatusCode = $exception->getHttpStatusCode();

        $message = sprintf(
            'OIDC error response: %s - %s',
            $exception->getErrorType(),
            $exception->getMessage(),
        );

        $context = ['httpStatusCode' => $httpStatusCode];
        if (($hint = $exception->getHint()) !== null) {
            $context['hint'] = $hint;
        }
        if (($previous = $exception->getPrevious()) !== null) {
            $context['previous'] = $previous->getMessage();
        }

        if ($httpStatusCode >= 500) {
            $this->loggerService->error($message, $context);
        } elseif ($httpStatusCode === 401 || $httpStatusCode === 403) {
            $this->loggerService->warning($message, $context);
        } else {
            $this->loggerService->notice($message, $context);
        }
    }

    private function logUnexpectedException(Throwable $exception): void
    {
        $context = ['exception' => $exception::class];
        if (($previous = $exception->getPrevious()) !== null) {
            $context['previous'] = $previous->getMessage();
        }

        $this->loggerService->error(
            'OIDC unexpected error response: ' . $exception->getMessage(),
            $context,
        );
    }
}
