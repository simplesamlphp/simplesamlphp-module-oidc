<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

use SensitiveParameter;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

/**
 * An authorization server this OP asks about a token it did not issue (AARC-G052 proxied token introspection):
 * the next hop, or the one the issuer map names for a given issuer.
 *
 * Built from configuration only. Nothing about an upstream is ever derived from a presented token.
 */
class IntrospectionUpstream
{
    public function __construct(
        protected readonly string $issuer,
        protected readonly string $introspectionEndpoint,
        protected readonly string $clientId,
        #[SensitiveParameter]
        protected readonly string $clientSecret,
        protected readonly ClientAuthenticationMethodsEnum $clientAuthenticationMethod,
        protected readonly float $connectTimeout,
        protected readonly float $timeout,
    ) {
    }


    /**
     * Whether the value is usable as an issuer identifier: "a URL that uses the "https" scheme and has no query
     * or fragment components" (RFC 8414 section 2), and no user or password either, which no issuer identifier
     * has any use for. Asked of an upstream's own issuer, and of the issuer a presented token names.
     */
    public static function isIssuerIdentifier(string $value): bool
    {
        $parts = parse_url($value);

        return is_array($parts) &&
        strtolower($parts['scheme'] ?? '') === 'https' &&
        ($parts['host'] ?? '') !== '' &&
        !isset($parts['user']) &&
        !isset($parts['pass']) &&
        !isset($parts['query']) &&
        !isset($parts['fragment']);
    }


    public function getIssuer(): string
    {
        return $this->issuer;
    }


    public function getIntrospectionEndpoint(): string
    {
        return $this->introspectionEndpoint;
    }


    public function getClientId(): string
    {
        return $this->clientId;
    }


    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }


    public function getClientAuthenticationMethod(): ClientAuthenticationMethodsEnum
    {
        return $this->clientAuthenticationMethod;
    }


    public function getConnectTimeout(): float
    {
        return $this->connectTimeout;
    }


    public function getTimeout(): float
    {
        return $this->timeout;
    }
}
