<?php

namespace SimpleSAML\Module\oidc\Entity\Interfaces;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface as OAuth2AuthCodeEntityInterface;

interface AuthCodeEntityInterface extends OAuth2AuthCodeEntityInterface
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
