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
     * @param string $message Error message
     * @param int $code Error code
     * @param string $errorType Error type
     * @param int $httpStatusCode HTTP status code to send (default = 400)
     * @param null|string $hint A helper hint
     * @param null|string $redirectUri A HTTP URI to redirect the user back to
     * @param Throwable|null $previous Previous exception
     * @param string|null $state
     */
    public function __construct(
        $message,
        $code,
        $errorType,
        $httpStatusCode = 400,
        $hint = null,
        $redirectUri = null,
        Throwable $previous = null,
        string $state = null
    ) {
        parent::__construct($message, $code, $errorType, $httpStatusCode, $hint, $redirectUri, $previous);

        $payload = [
            'error' => $errorType,
            'error_description' => $message,
        ];

        if ($state !== null) {
            $payload['state'] = $state;
        }

        $this->payload = $payload;
    }

    /**
     * Unsupported response type error.
     *
     * @param string|null $redirectUri
     * @param string|null $state
     * @return self
     */
    public static function unsupportedResponseType(
        string $redirectUri = null,
        string $state = null
    ): OidcServerException {
        $errorMessage = 'The response type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        return new self($errorMessage, 2, 'unsupported_response_type', 400, $hint, $redirectUri, null, $state);
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

    /**
     * Updates the current payload.
     *
     * @param array $payload
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }
}
