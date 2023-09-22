<?php

namespace SimpleSAML\Test\Module\oidc;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;

/**
 * @covers \SimpleSAML\Module\oidc\ModuleConfig
 */
class ModuleConfigTest extends TestCase
{
    public function testSigningKeyNameCanBeCustomized(): void
    {
        $certDir = '/tmp/cert/';
        Configuration::clearInternalState();
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'certdir' => $certDir
                ]
            )
        );
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray([]),
            'module_oidc.php'
        );
        // Test default cert and pem
        $moduleConfig = new \SimpleSAML\Module\oidc\ModuleConfig();
        $this->assertEquals($certDir . 'oidc_module.crt', $moduleConfig->getCertPath());
        $this->assertEquals($certDir . 'oidc_module.key', $moduleConfig->getPrivateKeyPath());

        // Set customized
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(
                [
                    'privatekey' => 'myPrivateKey.key',
                    'certificate' => 'myCertificate.crt',
                ]
            ),
            'module_oidc.php'
        );
        $moduleConfig = new \SimpleSAML\Module\oidc\ModuleConfig();
        $this->assertEquals($certDir . 'myCertificate.crt', $moduleConfig->getCertPath());
        $this->assertEquals($certDir . 'myPrivateKey.key', $moduleConfig->getPrivateKeyPath());
    }
}
