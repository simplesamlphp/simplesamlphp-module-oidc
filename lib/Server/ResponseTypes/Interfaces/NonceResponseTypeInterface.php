<?php

namespace SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\Interfaces;

interface NonceResponseTypeInterface
{
    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce): void;

    /**
     * @return string|null
     */
    public function getNonce();
}
