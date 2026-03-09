<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ModuleConfig;

class OAuth2Bridge
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * Bridge `encrypt` function, which can be used instead of
     * \League\OAuth2\Server\CryptTrait::encrypt()
     *
     * @param string $unencryptedData
     * @param Key|string $encryptionKey
     * @return string
     * @throws OidcException
     */
    public function encrypt(
        string $unencryptedData,
        null|Key|string $encryptionKey = null,
    ): string {
        $encryptionKey ??= $this->moduleConfig->getEncryptionKey();

        try {
            return $encryptionKey instanceof Key ?
            Crypto::encrypt($unencryptedData, $encryptionKey) :
            Crypto::encryptWithPassword($unencryptedData, $encryptionKey);
        } catch (\Exception $e) {
            throw new OidcException('Error encrypting data: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }
    }

    /**
     * Bridge `decrypt` function, which can be used instead of
     * \League\OAuth2\Server\CryptTrait::decrypt()
     *
     * @param string $encryptedData
     * @param Key|string $encryptionKey
     * @return string
     * @throws OidcException
     */
    public function decrypt(
        string $encryptedData,
        null|Key|string $encryptionKey = null,
    ): string {
        $encryptionKey ??= $this->moduleConfig->getEncryptionKey();

        try {
            return $encryptionKey instanceof Key ?
            Crypto::decrypt($encryptedData, $encryptionKey) :
            Crypto::decryptWithPassword($encryptedData, $encryptionKey);
        } catch (\Exception $e) {
            throw new OidcException('Error decrypting data: ' . $e->getMessage(), (int)$e->getCode(), $e);
        }
    }
}
