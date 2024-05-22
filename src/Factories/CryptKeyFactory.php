<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\ModuleConfig;

class CryptKeyFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * @throws \Exception
     */
    public function buildPrivateKey(): CryptKey
    {
        return new CryptKey(
            $this->moduleConfig->getPrivateKeyPath(),
            $this->moduleConfig->getPrivateKeyPassPhrase(),
        );
    }

    /**
     * @throws \Exception
     */
    public function buildPublicKey(): CryptKey
    {
        return new CryptKey($this->moduleConfig->getCertPath());
    }
}
