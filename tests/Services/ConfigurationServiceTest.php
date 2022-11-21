<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use PHPUnit\Framework\TestCase;

class ConfigurationServiceTest extends TestCase
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
        $service = new ConfigurationService();
        $this->assertEquals($certDir . 'oidc_module.crt', $service->getCertPath());
        $this->assertEquals($certDir . 'oidc_module.key', $service->getPrivateKeyPath());

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
        $service = new ConfigurationService();
        $this->assertEquals($certDir . 'myCertificate.crt', $service->getCertPath());
        $this->assertEquals($certDir . 'myPrivateKey.key', $service->getPrivateKeyPath());
    }
}
