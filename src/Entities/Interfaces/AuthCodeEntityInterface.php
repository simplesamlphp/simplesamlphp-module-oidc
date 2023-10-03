<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface as OAuth2AuthCodeEntityInterface;

interface AuthCodeEntityInterface extends OAuth2AuthCodeEntityInterface
{
    /**
     * @return string|null
     */
    public function getNonce(): ?string;

    public function setNonce(string $nonce): void;
}
