<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\Exceptions;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\OpenID\Codebooks\ErrorsEnum;
use Throwable;

use function json_encode;

class OidcServerException extends OAuthServerException
{
    /**
     * @var array
     */
    protected array $payload;

    /**
     * @var int
     * @psalm-suppress PossiblyUnusedProperty Property is private in parent.
     */
    protected int $httpStatusCode;

    /**
     * @var string
     * @psalm-suppress PossiblyUnusedProperty Property is private in parent.
     */
    protected string $errorType;

    /**
     * @var null|string
     */
    protected ?string $redirectUri;

    /**
     * @var null|ResponseModeInterface
     */
    protected ?ResponseModeInterface $responseMode = null;

    /**
     * Throw a new exception.
     *
     * @param string $message Error message
     * @param int $code Error code
     * @param string $errorType Error type
     * @param int $httpStatusCode HTTP status code to send (default = 400)
     * @param null|string $hint A helper hint
     * @param null|string $redirectUri An HTTP URI to redirect the user back to
     * @param \Throwable|null $previous Previous exception
     * @param string|null $state
     */
    public function __construct(
        string $message,
        int $code,
        string $errorType,
        int $httpStatusCode = 400,
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ) {
        parent::__construct($message, $code, $errorType, $httpStatusCode, $hint, $redirectUri, $previous);

        $this->httpStatusCode = $httpStatusCode;
        $this->errorType = $errorType;
        $this->redirectUri = $redirectUri;
        $this->responseMode = $responseMode;

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
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return OidcServerException
     */
    public static function unsupportedResponseType(
        ?string $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = 'The response type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        return new self(
            $errorMessage,
            2,
            'unsupported_response_type',
            400,
            $hint,
            $redirectUri,
            null,
            $state,
            $responseMode,
        );
    }

    /**
     * Invalid scope error.
     *
     * @param string $scope The bad scope
     * @param string|null $redirectUri An HTTP URI to redirect the user back to
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return OidcServerException
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidScope(
        $scope,
        $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        if (empty($scope)) {
            $hint = 'Specify a scope in the request or set a default scope';
        } else {
            $hint = sprintf(
                'Check the `%s` scope',
                htmlspecialchars($scope, ENT_QUOTES, 'UTF-8', false),
            );
        }

        $e = new self(
            'The requested scope is invalid, unknown, or malformed',
            5,
            'invalid_scope',
            400,
            $hint,
            $redirectUri,
            null,
            $state,
            $responseMode,
        );

        return $e;
    }

    /**
     * Invalid request error with redirect ability.
     *
     * @param string $parameter
     * @param string|null $hint
     * @param \Throwable|null $previous
     * @param string|null $redirectUri
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return OidcServerException
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRequest(
        $parameter,
        $hint = null,
        ?Throwable $previous = null,
        ?string $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = 'The request is missing a required parameter, includes an invalid parameter value, ' .
        'includes a parameter more than once, or is otherwise malformed.';
        $hint = ($hint === null) ? \sprintf('Check the `%s` parameter', $parameter) : $hint;
        $e = new self($errorMessage, 9, 'invalid_request', 400, $hint, $redirectUri, $previous, $state, $responseMode);

        return $e;
    }

    /**
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return OidcServerException
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function accessDenied(
        $hint = null,
        $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $e = new self(
            'The resource owner or authorization server denied the request.',
            9,
            'access_denied',
            401,
            $hint,
            $redirectUri,
            $previous,
            $state,
            $responseMode,
        );

        return $e;
    }

    /**
     * Prompt none requires that user should be authenticated.
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     *
     * @return OidcServerException
     */
    public static function loginRequired(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = "End-User is not already authenticated.";

        $e = new self($errorMessage, 6, 'login_required', 400, $hint, $redirectUri, $previous, $state, $responseMode);

        return $e;
    }

    /**
     * Request object not supported.
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     *
     * @return OidcServerException
     */
    public static function requestNotSupported(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = "Request object not supported.";

        $e = new self(
            $errorMessage,
            7,
            'request_not_supported',
            400,
            $hint,
            $redirectUri,
            $previous,
            $state,
            $responseMode,
        );

        return $e;
    }

    /**
     * Invalid refresh token.
     *
     * @param string|null $hint
     * @param \Throwable|null $previous
     *
     * @return OidcServerException
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRefreshToken($hint = null, ?Throwable $previous = null): OidcServerException
    {
        return new self('The refresh token is invalid.', 8, 'invalid_grant', 400, $hint, null, $previous);
    }

    public static function invalidTrustChain(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = 'Trust chain validation failed.';

        $e = new self(
            $errorMessage,
            12,
            ErrorsEnum::InvalidTrustChain->value,
            400,
            $hint,
            $redirectUri,
            $previous,
            $state,
            $responseMode,
        );

        return $e;
    }

    /**
     * Forbidden request.
     *
     * @param string|null $hint
     * @param \Throwable|null $previous
     *
     * @return self
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function forbidden(?string $hint = null, ?Throwable $previous = null): OidcServerException
    {
        return new self(
            'Request understood, but refused to process it.',
            11,
            'forbidden',
            403,
            $hint,
            null,
            $previous,
        );
    }

    /**
     * Invalid client metadata error, as defined by the OAuth 2.0 Dynamic Client
     * Registration Protocol (RFC 7591, section 3.2.2) and OpenID Connect
     * Dynamic Client Registration. The value of one of the client metadata
     * fields is invalid, and the server has rejected this request.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
     *
     * @param string|null $hint
     * @param \Throwable|null $previous
     *
     * @return self
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidClientMetadata(
        ?string $hint = null,
        ?Throwable $previous = null,
    ): OidcServerException {
        return new self(
            'The value of one of the client metadata fields is invalid and the server has rejected this request.',
            13,
            'invalid_client_metadata',
            400,
            $hint,
            null,
            $previous,
        );
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
    public function setPayload(array $payload): void
    {
        $this->payload = $payload;
    }

    /**
     * @param string|null $redirectUri Set to string, or unset it with null
     */
    public function setRedirectUri(?string $redirectUri = null): void
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
    public function setState(?string $state = null): void
    {
        if ($state === null) {
            unset($this->payload['state']);
            return;
        }

        $this->payload['state'] = $state;
    }

    /**
     * Generate an HTTP response.
     *
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param bool $useFragment
     * @param int $jsonOptions options passed to json_encode
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function generateHttpResponse(
        ResponseInterface $response,
        $useFragment = false,
        $jsonOptions = 0,
    ): ResponseInterface {
        /** @var array<string,string> $headers */
        $headers = $this->getHttpHeaders();

        $payload = $this->getPayload();

        if ($this->responseMode === null) {
            // Fallback to useFragment if responseMode is not set
            $this->responseMode = $useFragment ? new FragmentResponseMode() : new QueryResponseMode();
        }

        if ($this->redirectUri !== null) {
            return $this->responseMode->buildResponse($this->redirectUri, $payload)->generateHttpResponse($response);
        }

        foreach ($headers as $header => $content) {
            $response = $response->withHeader($header, $content);
        }

        $responseBody = json_encode($payload, $jsonOptions) ?: 'JSON encoding of payload failed';

        $response->getBody()->write($responseBody);

        return $response->withStatus($this->getHttpStatusCode());
    }
}
