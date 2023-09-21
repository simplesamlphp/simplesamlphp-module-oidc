<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\CryptKey;

class CryptKeyFactory
{
    public function __construct(
        private string $publicKeyPath,
        private string $privateKeyPath,
        private ?string $passPhrase = null
    ) {
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
