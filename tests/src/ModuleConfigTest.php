<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc;

use Exception;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * @covers \SimpleSAML\Module\oidc\ModuleConfig
 */
class ModuleConfigTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testSigningKeyNameCanBeCustomized(): void
    {
        $certDir = '/tmp/cert/';
        Configuration::clearInternalState();
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'certdir' => $certDir,
                ],
            ),
        );
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray([]),
            ModuleConfig::DEFAULT_FILE_NAME,
        );
        // Test default cert and pem
        $moduleConfig = new ModuleConfig();
        $this->assertEquals($certDir . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME, $moduleConfig->getCertPath());
        $this->assertEquals(
            $certDir . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            $moduleConfig->getPrivateKeyPath(),
        );

        // Set customized
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    ModuleConfig::OPTION_PKI_PRIVATE_KEY_FILENAME => 'myPrivateKey.key',
                    ModuleConfig::OPTION_PKI_CERTIFICATE_FILENAME => 'myCertificate.crt',
                ],
            ),
            ModuleConfig::DEFAULT_FILE_NAME,
        );
        $moduleConfig = new ModuleConfig();
        $this->assertEquals($certDir . 'myCertificate.crt', $moduleConfig->getCertPath());
        $this->assertEquals($certDir . 'myPrivateKey.key', $moduleConfig->getPrivateKeyPath());
    }
}
