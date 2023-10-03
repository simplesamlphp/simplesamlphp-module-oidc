<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Traits;

use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;

trait OidcAuthCodeTrait
{
    use AuthCodeTrait;

    /**
     * @var null|string
     */
    protected ?string $nonce = null;

    /**
     * @inheritDoc
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }
}
