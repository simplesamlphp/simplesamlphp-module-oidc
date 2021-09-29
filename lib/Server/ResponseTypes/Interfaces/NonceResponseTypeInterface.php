<?php

namespace SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces;

interface NonceResponseTypeInterface
{
    /**
     * @param string|null $nonce
     */
    public function setNonce(?string $nonce): void;

    /**
     * @return string|null
     */
    public function getNonce(): ?string;
}
