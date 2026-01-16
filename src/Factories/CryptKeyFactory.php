<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Error\ConfigurationError;
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
        $defaultSignatureKeyPairConfig = $this->getDefaultProtocolSignatureKeyPairConfig();

        $privateKeyFilename = $defaultSignatureKeyPairConfig[ModuleConfig::KEY_PRIVATE_KEY_FILENAME];
        $privateKeyPassword = $defaultSignatureKeyPairConfig[ModuleConfig::KEY_PRIVATE_KEY_PASSWORD] ?? null;

        return new CryptKey(
            $privateKeyFilename,
            $privateKeyPassword,
            true,
        );
    }

    /**
     * @throws \Exception
     */
    public function buildPublicKey(): CryptKey
    {
        $defaultSignatureKeyPairConfig = $this->getDefaultProtocolSignatureKeyPairConfig();
        $publicKeyFilename = $defaultSignatureKeyPairConfig[ModuleConfig::KEY_PUBLIC_KEY_FILENAME];
        return new CryptKey($publicKeyFilename, null, false);
    }

    /**
     * @return array{
     *      algorithm: \SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum,
     *      private_key_filename: non-empty-string,
     *      public_key_filename: non-empty-string,
     *      private_key_password: ?non-empty-string,
     *      key_id: ?non-empty-string
     *  }
     * @throws ConfigurationError
     *
     */
    protected function getDefaultProtocolSignatureKeyPairConfig(): array
    {
        $defaultProtocolKeyPair = $this->moduleConfig->getProtocolSignatureKeyPairs();

        /** @psalm-suppress MixedAssignment */
        $defaultProtocolKeyPair = $defaultProtocolKeyPair[array_key_first($defaultProtocolKeyPair)];

        if (!is_array($defaultProtocolKeyPair)) {
            throw new ConfigurationError('Invalid protocol signature key pairs config.');
        }

        return $this->moduleConfig->getValidatedSignatureKeyPairArray($defaultProtocolKeyPair);
    }
}
