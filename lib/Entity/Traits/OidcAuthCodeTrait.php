<?php

namespace SimpleSAML\Modules\OpenIDConnect\Entity\Traits;

use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;

trait OidcAuthCodeTrait
{
    use AuthCodeTrait;

    /**
     * @var null|string
     */
    protected $nonce;

    /**
     * @var null|\stdClass
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
     * @return \stdClass|null
     */
    public function getClaims(): ?\stdClass
    {
        return $this->claims;
    }

    /**
     * @param \stdClass|null $claims
     */
    public function setClaims(?\stdClass $claims): void
    {
        $this->claims = $claims;
    }
}
