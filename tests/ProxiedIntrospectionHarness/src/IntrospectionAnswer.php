<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\ProxiedIntrospectionHarness;

/**
 * An introspection endpoint's HTTP answer, as a harness test received it.
 */
final readonly class IntrospectionAnswer
{
    /**
     * @param string $wwwAuthenticate The WWW-Authenticate header field, empty when there is none.
     */
    public function __construct(
        public int $status,
        public string $contentType,
        public string $body,
        public string $wwwAuthenticate = '',
    ) {
    }


    /**
     * The body as a JSON object, or null when it is not one.
     *
     * @return ?array<string, mixed>
     */
    public function json(): ?array
    {
        $decoded = json_decode($this->body, true);

        return is_array($decoded) ? $decoded : null;
    }


    public function describe(): string
    {
        return sprintf('HTTP %d, %s: %s', $this->status, $this->contentType, $this->body);
    }
}
