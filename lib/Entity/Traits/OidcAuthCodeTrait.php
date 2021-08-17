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
     * @var null|array
     */
    protected $claims;

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

    /**
     * @return array|null
     */
    public function getClaims(): ?array
    {
        return $this->claims;
    }

    /**
     * @param array|null $claims
     */
    public function setClaims(?array $claims): void
    {
        $this->claims = $claims;
    }
}
