<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Error\Error;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class ErrorResponder
{
    /**
     * What an `error_description` may not hold. RFC 6749 allows %x20-21 / %x23-5B / %x5D-7E in one (sections
     * 4.1.2.1, 4.2.2.1 and 5.2): printable ASCII without the double quote and the backslash. OpenID4VCI 1.0
     * section 8.3.1.2 has the same rule for Credential Request errors. Many descriptions carry an exception message
     * or a value from the request, so they are not kept to it where they are written; the characters outside it
     * are dropped rather than escaped, since no escape is allowed either.
     */
    public const string ERROR_DESCRIPTION_DISALLOWED_CHARACTERS = '/[^\x20\x21\x23-\x5B\x5D-\x7E]/';


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
            $this->keepTheDescriptionToItsCharacters($exception);

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
     *
     * A protected resource's refusal of an access token carries its challenge (RFC 6750 section 3), and a refusal
     * for want of one carries nothing else: no body, and so no error code (RFC 6750 section 3.1). A client which
     * failed to authenticate through the Authorization header gets the challenge of its scheme (`invalid_client`,
     * RFC 6749 section 5.2), which League adds.
     */
    public function forExceptionJson(OAuthServerException $exception): Response
    {
        $this->logOAuthServerException($exception);

        $headers = ['Cache-Control' => 'no-cache, no-store'];

        if (($challenge = $exception->getHttpHeaders()['WWW-Authenticate'] ?? null) !== null) {
            $headers['WWW-Authenticate'] = $challenge;
        }

        if ($exception instanceof OidcServerException && !$exception->hasBody()) {
            return new Response('', $exception->getHttpStatusCode(), $headers);
        }

        $body = [
            'error' => $exception->getErrorType(),
            'error_description' => (string)preg_replace(
                self::ERROR_DESCRIPTION_DISALLOWED_CHARACTERS,
                '',
                $exception->getMessage(),
            ),
        ];

        if (($hint = $exception->getHint()) !== null) {
            $body['hint'] = $hint;
        }

        return new JsonResponse(
            $body,
            $exception->getHttpStatusCode(),
            $headers,
        );
    }


    /**
     * The payload League renders, in a JSON body or in the redirect URI, with the description kept to the
     * characters it may hold (ERROR_DESCRIPTION_DISALLOWED_CHARACTERS).
     */
    private function keepTheDescriptionToItsCharacters(OAuthServerException $exception): void
    {
        $payload = $exception->getPayload();

        if (isset($payload['error_description'])) {
            $payload['error_description'] = (string)preg_replace(
                self::ERROR_DESCRIPTION_DISALLOWED_CHARACTERS,
                '',
                $payload['error_description'],
            );
            $exception->setPayload($payload);
        }
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
