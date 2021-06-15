<?php

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use League\OAuth2\Server\CryptKey;

class CryptKeyFactory
{
    /**
     * @var string
     */
    private $publicKeyPath;
    /**
     * @var string
     */
    private $privateKeyPath;
    /**
     * @var string|null
     */
    private $passPhrase;

    public function __construct(
        string $publicKeyPath,
        string $privateKeyPath,
        string $passPhrase = null
    ) {
        $this->publicKeyPath = $publicKeyPath;
        $this->privateKeyPath = $privateKeyPath;
        $this->passPhrase = $passPhrase;
    }

    public function buildPrivateKey(): CryptKey
    {
        return new CryptKey($this->privateKeyPath, $this->passPhrase);
    }

    public function buildPublicKey(): CryptKey
    {
        return new CryptKey($this->publicKeyPath);
    }
}
