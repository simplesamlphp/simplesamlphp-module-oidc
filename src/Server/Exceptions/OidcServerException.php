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
     * @var null|string
     */
    protected ?string $redirectUri = null;

    /**
     * @var null|ResponseModeInterface
     */
    protected ?ResponseModeInterface $responseMode = null;

    private static function create(
        string $message,
        int $code,
        string $errorType,
        int $httpStatusCode = 400,
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): static {
        $exception = new static($message, $code, $errorType, $httpStatusCode, $hint, $redirectUri, $previous);

        $exception->redirectUri = $redirectUri;
        $exception->responseMode = $responseMode;

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

        $exception->setPayload($payload);

        return $exception;
    }

    /**
     * Unsupported response type error.
     *
     * @param string|null $redirectUri
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return static
     */
    public static function unsupportedResponseType(
        ?string $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = 'The response type is not supported by the authorization server.';
        $hint = 'Check that all required parameters have been provided';

        return self::create(
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
     * @return static
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidScope(
        string $scope,
        ?string $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): static {
        if (empty($scope)) {
            $hint = 'Specify a scope in the request or set a default scope';
        } else {
            $hint = sprintf(
                'Check the `%s` scope',
                htmlspecialchars($scope, ENT_QUOTES, 'UTF-8', false),
            );
        }

        $e = self::create(
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
     * @return static
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRequest(
        string $parameter,
        ?string $hint = null,
        ?Throwable $previous = null,
        ?string $redirectUri = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): static {
        $errorMessage = 'The request is missing a required parameter, includes an invalid parameter value, ' .
        'includes a parameter more than once, or is otherwise malformed.';
        $hint = ($hint === null) ? \sprintf('Check the `%s` parameter', $parameter) : $hint;
        $e = self::create(
            $errorMessage,
            9,
            'invalid_request',
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
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     * @return static
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function accessDenied(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): static {
        $e = self::create(
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
     * The authenticated client is not authorized to use this authorization grant type or response type
     * (RFC 6749 sections 4.1.2.1 / 5.2).
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     */
    public static function unauthorizedClient(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): static {
        return self::create(
            'The client is not authorized to request a token using this method.',
            10,
            'unauthorized_client',
            400,
            $hint,
            $redirectUri,
            $previous,
            $state,
            $responseMode,
        );
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
     * @return static
     */
    public static function loginRequired(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = "End-User is not already authenticated.";

        $e = self::create(
            $errorMessage,
            6,
            'login_required',
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
     * Request object not supported.
     *
     * @param string|null $hint
     * @param string|null $redirectUri
     * @param \Throwable|null $previous
     * @param string|null $state
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     *
     * @return static
     */
    public static function requestNotSupported(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = "Request object not supported.";

        $e = self::create(
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
     * @return static
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRefreshToken(?string $hint = null, ?Throwable $previous = null): static
    {
        return self::create('The refresh token is invalid.', 8, 'invalid_grant', 400, $hint, null, $previous);
    }

    public static function invalidTrustChain(
        ?string $hint = null,
        ?string $redirectUri = null,
        ?Throwable $previous = null,
        ?string $state = null,
        ?ResponseModeInterface $responseMode = null,
    ): OidcServerException {
        $errorMessage = 'Trust chain validation failed.';

        $e = self::create(
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
        return self::create(
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
        return self::create(
            'The value of one of the client metadata fields is invalid and the server has rejected this request.',
            13,
            ErrorsEnum::InvalidClientMetadata->value,
            400,
            $hint,
            null,
            $previous,
        );
    }

    /**
     * Invalid redirect URI error, as defined by the OAuth 2.0 Dynamic Client
     * Registration Protocol (RFC 7591, section 3.2.2) and OpenID Connect
     * Dynamic Client Registration 1.0 (section 3.3). The value of one or more
     * redirect_uris is invalid.
     *
     * @see https://www.rfc-editor.org/rfc/rfc7591#section-3.2.2
     *
     * @param string|null $hint
     * @param \Throwable|null $previous
     *
     * @return self
     * @psalm-suppress LessSpecificImplementedReturnType
     */
    public static function invalidRedirectUri(
        ?string $hint = null,
        ?Throwable $previous = null,
    ): OidcServerException {
        return self::create(
            'The value of one or more redirect_uris is invalid.',
            14,
            ErrorsEnum::InvalidRedirectUri->value,
            400,
            $hint,
            null,
            $previous,
        );
    }

    /**
     * Returns the current payload.
     *
     * @return array<string, string>
     */
    public function getPayload(): array
    {
        return parent::getPayload();
    }

    /**
     * Updates the current payload.
     *
     * @param array<string, string> $payload
     */
    public function setPayload(array $payload): void
    {
        parent::setPayload($payload);
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
            $payload = $this->getPayload();
            unset($payload['state']);
            $this->setPayload($payload);
            return;
        }

        $payload = $this->getPayload();
        $payload['state'] = $state;
        $this->setPayload($payload);
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
