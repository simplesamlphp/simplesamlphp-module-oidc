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
     * @inheritDoc
     */
    public function getNonce()
    {
        return $this->nonce;
    }

    /**
     * @inheritDoc
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }
}
