<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class OidcServerException extends OAuthServerException
{
    /**
     * @var array
     */
    protected $payload;

    /**
     * @var int
     */
    protected $httpStatusCode;

    /**
     * @var string
     */
    protected $errorType;

    /**
     * @var null|string
     */
    protected $redirectUri;

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
        string $message,
        int $code,
        string $errorType,
        int $httpStatusCode = 400,
        string $hint = null,
        string $redirectUri = null,
        Throwable $previous = null,
        string $state = null
    ) {
        parent::__construct($message, $code, $errorType, $httpStatusCode, $hint, $redirectUri, $previous);

        $this->httpStatusCode = $httpStatusCode;
        $this->errorType = $errorType;
        $this->redirectUri = $redirectUri;

        if ($hint !== null) {
            $message .= ' (' . $hint . ')';
        }

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
     * Invalid scope error.
     *
     * @param string $scope The bad scope
     * @param string|null $redirectUri A HTTP URI to redirect the user back to
     * @param string|null $state
     * @return static
     */
    public static function invalidScope($scope, $redirectUri = null, string $state = null): OidcServerException
    {
        // OAuthServerException correctly implements this error, however, it misses state parameter.
        $e = parent::invalidScope($scope, $redirectUri);
        $e->setState($state);

        return $e;
    }

    /**
     * Invalid request error with redirect ability.
     *
     * @param string $parameter
     * @param string|null $hint
     * @param Throwable|null $previous
     * @param string|null $redirectUri
     * @param string|null $state
     * @return static
     */
    public static function invalidRequest(
        $parameter,
        $hint = null,
        Throwable $previous = null,
        string $redirectUri = null,
        string $state = null
    ): OidcServerException {
        $e = parent::invalidRequest($parameter, $hint, $previous);
        // OAuthServerException misses the ability to set redirectUri for invalid requests, as well as state.
        $e->setRedirectUri($redirectUri);
        $e->setState($state);

        return $e;
    }

    /**
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param Throwable|null $previous
     * @param string|null $state
     * @return static
     */
    public static function accessDenied(
        $hint = null,
        $redirectUri = null,
        Throwable $previous = null,
        string $state = null
    ): OidcServerException {
        $e = parent::accessDenied($hint, $redirectUri, $previous);
        $e->setState($state);

        return $e;
    }

    /**
     * Prompt none requires that user should be authenticated.
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param Throwable|null $previous
     * @param string|null $state
     *
     * @return self
     */
    public static function loginRequired(
        $hint = null,
        $redirectUri = null,
        Throwable $previous = null,
        $state = null
    ): OidcServerException {
        $errorMessage = "End-User is not already authenticated.";

        return new self($errorMessage, 6, 'login_required', 400, $hint, $redirectUri, $previous, $state);
    }

    /**
     * Prompt none requires that user should be authenticated.
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param Throwable|null $previous
     * @param string|null $state
     *
     * @return self
     */
    public static function requestNotSupported(
        $hint = null,
        $redirectUri = null,
        Throwable $previous = null,
        $state = null
    ): OidcServerException {
        $errorMessage = "Request object not supported.";

        return new self($errorMessage, 7, 'request_not_supported', 400, $hint, $redirectUri, $previous, $state);
    }

    /**
     * Invalid refresh token.
     *
     * @param null|string $hint
     * @param Throwable   $previous
     *
     * @return self
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRefreshToken($hint = null, Throwable $previous = null)
    {
        return new self('The refresh token is invalid.', 8, 'invalid_grant', 400, $hint, null, $previous);
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

    /**
     * @param string|null $redirectUri Set to string, or unset it with null
     */
    public function setRedirectUri(string $redirectUri = null): void
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * Check if the exception has an associated redirect URI.
     *
     * Returns whether the exception includes a redirect, since
     * getHttpStatusCode() doesn't return a 302 when there's a
     * redirect enabled. This helps when you want to override local
     * error pages but want to let redirects through.
     *
     * @return bool
     */
    public function hasRedirect(): bool
    {
        return $this->redirectUri !== null;
    }

    /**
     * Returns the Redirect URI used for redirecting.
     *
     * @return string|null
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    /**
     * @param string|null $state Set to string, or unset it with null
     */
    public function setState(string $state = null): void
    {
        if ($state === null) {
            unset($this->payload['state']);
            return;
        }

        $this->payload['state'] = $state;
    }

    /**
     * Generate a HTTP response.
     *
     * @param ResponseInterface $response
     * @param bool              $useFragment True if errors should be in the URI fragment instead of query string
     * @param int               $jsonOptions options passed to json_encode
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(
        ResponseInterface $response,
        $useFragment = false,
        $jsonOptions = 0
    ): ResponseInterface {
        $headers = $this->getHttpHeaders();

        $payload = $this->getPayload();

        if ($this->redirectUri !== null) {
            if ($useFragment === true) {
                $this->redirectUri .= (\strstr($this->redirectUri, '#') === false) ? '#' : '&';
            } else {
                $this->redirectUri .= (\strstr($this->redirectUri, '?') === false) ? '?' : '&';
            }

            return $response->withStatus(302)->withHeader('Location', $this->redirectUri . \http_build_query($payload));
        }

        foreach ($headers as $header => $content) {
            $response = $response->withHeader($header, $content);
        }

        $responseBody = \json_encode($payload, $jsonOptions) ?: 'JSON encoding of payload failed';

        $response->getBody()->write($responseBody);

        return $response->withStatus($this->getHttpStatusCode());
    }
}
