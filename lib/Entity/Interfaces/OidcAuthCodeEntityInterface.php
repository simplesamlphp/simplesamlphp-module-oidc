<?php

namespace SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;

interface OidcAuthCodeEntityInterface extends AuthCodeEntityInterface
{
    /**
     * @return string|null
     */
    public function getNonce(): ?string;

    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce): void;
}
