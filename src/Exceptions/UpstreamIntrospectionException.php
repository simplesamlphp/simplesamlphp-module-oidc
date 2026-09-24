<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Exceptions;

use RuntimeException;
use Throwable;

/**
 * This OP did not get an answer about a token from the authorization server it asked upstream (AARC-G052 proxied
 * token introspection): the request failed, was refused, or came back as something other than an introspection
 * response.
 *
 * Never a verdict on the token. The token may be perfectly valid; this OP only failed to find out, and a resource
 * server told "active: false" instead could cache that answer and refuse a valid token for as long as it keeps it.
 */
class UpstreamIntrospectionException extends RuntimeException
{
    /**
     * @param bool $isOwnFault Whether the failure is this deployment's to fix rather than the upstream's: its
     * credentials refused, or its own destination policy refusing the configured endpoint.
     */
    protected function __construct(
        string $message,
        protected readonly bool $isOwnFault = false,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }


    /**
     * The upstream could not be reached, took too long, or answered with an HTTP error of its own.
     */
    public static function unavailable(string $message, ?Throwable $previous = null): self
    {
        return new self($message, false, $previous);
    }


    /**
     * The upstream answered, but not with an introspection response this OP can read.
     */
    public static function malformedResponse(string $message, ?Throwable $previous = null): self
    {
        return new self($message, false, $previous);
    }


    /**
     * The upstream refused this OP's own credentials (HTTP 401 or 403), or this OP's own configuration refused
     * the request (the destination policy, the HTTP client options): a misconfiguration here, which no retry
     * will cure.
     */
    public static function ownFault(string $message, ?Throwable $previous = null): self
    {
        return new self($message, true, $previous);
    }


    public function isOwnFault(): bool
    {
        return $this->isOwnFault;
    }
}
