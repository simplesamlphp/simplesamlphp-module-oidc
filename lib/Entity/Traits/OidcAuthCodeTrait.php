<?php

namespace SimpleSAML\Module\oidc\Entity\Traits;

use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;

trait OidcAuthCodeTrait
{
    use AuthCodeTrait;

    /**
     * @var null|string
     */
    protected $nonce;

    /**
     * @inheritDoc
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @inheritDoc
     */
    public function setNonce($nonce): void
    {
        $this->nonce = $nonce;
    }

}
