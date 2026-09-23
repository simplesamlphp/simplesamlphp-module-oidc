<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ValueAbstracts;

/**
 * Where a token being introspected comes from, as far as this OP can tell: issued here, or issued elsewhere
 * and answered for by an authorization server upstream (AARC-G052 proxied token introspection).
 */
class IntrospectedTokenOrigin
{
    protected function __construct(
        protected readonly bool $isLocal,
        protected readonly string $issuer,
        protected readonly bool $isIssuerVerified,
    ) {
    }


    /**
     * A token this OP issued, and has validated itself.
     */
    public static function local(string $issuer): self
    {
        return new self(true, $issuer, true);
    }


    /**
     * A token this OP did not issue.
     *
     * @param string $issuer The issuer the upstream answer names, when it names one; otherwise the one read out
     * of the presented token, whose signature nobody on this path has checked.
     * @param bool $isIssuerVerified Whether the issuer is the upstream answer's. AARC-G052 section 3 forbids
     * a proxy to change it, so it is the token-issuing authorization server's own statement.
     */
    public static function foreign(string $issuer, bool $isIssuerVerified): self
    {
        return new self(false, $issuer, $isIssuerVerified);
    }


    public function isLocal(): bool
    {
        return $this->isLocal;
    }


    public function getIssuer(): string
    {
        return $this->issuer;
    }


    public function isIssuerVerified(): bool
    {
        return $this->isIssuerVerified;
    }
}
