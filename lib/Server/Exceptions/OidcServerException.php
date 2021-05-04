<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException;
use Throwable;

class OidcServerException extends OAuthServerException
{
    /**
     * @var array
     */
    protected $payload;

    /**
     * Throw a new exception.
     *
     * @param string      $message        Error message
     * @param int         $code           Error code
     * @param string      $errorType      Error type
     * @param int         $httpStatusCode HTTP status code to send (default = 400)
     * @param null|string $hint           A helper hint
     * @param null|string $redirectUri    A HTTP URI to redirect the user back to
     * @param Throwable|null   $previous       Previous exception
     */
    public function __construct(
        $message,
        $code,
        $errorType,
        $httpStatusCode = 400,
        $hint = null,
        $redirectUri = null,
        Throwable $previous = null
    ) {
        parent::__construct($message, $code, $errorType, $httpStatusCode, $hint, $redirectUri, $previous);
        $this->payload = [
            'error'             => $errorType,
            'error_description' => $message,
        ];
    }

    /**
     * Unsupported response type error.
     *
     * @param string|null $redirectUri
     * @param array $additionalPayload
     * @return self
     */
    public static function unsupportedResponseType(
        string $redirectUri = null,
        array $additionalPayload = []
    ): OidcServerException {
        $errorMessage = 'The response type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        $exception = new self($errorMessage, 2, 'unsupported_response_type', 400, $hint, $redirectUri);
        $exception->setPayload(\array_merge($exception->getPayload(), $additionalPayload));

        return $exception;
    }

    /**
     * Updates the current payload.
     *
     * @param array $payload
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    /**
     * Returns the current payload.
     *
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }
}
