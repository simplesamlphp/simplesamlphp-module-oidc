<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Exception;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\JsonWebKeySetService;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;

/**
 * @covers \SimpleSAML\Module\oidc\Services\JsonWebKeySetService
 */
class JsonWebKeySetServiceTest extends TestCase
{
    private static string $pkGeneratePublic;

    /**
     * @return void
     * @throws \Exception
     */
    public static function setUpBeforeClass(): void
    {
        // From https://www.andrewzammit.com/blog/php-openssl-rsa-shared-key-generation/
        $pkGenerate = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        // get the public key
        $pkGenerateDetails = openssl_pkey_get_details($pkGenerate);
        self::$pkGeneratePublic = $pkGenerateDetails['key'];

        file_put_contents(sys_get_temp_dir() . '/oidc_module.crt', self::$pkGeneratePublic);

        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray([]),
            ModuleConfig::DEFAULT_FILE_NAME,
        );
    }

    /**
     * @return void
     */
    public static function tearDownAfterClass(): void
    {
        Configuration::clearInternalState();
        unlink(sys_get_temp_dir() . '/oidc_module.crt');
    }

    /**
     * @return void
     * @throws \SimpleSAML\Error\Exception
     */
    public function testKeys()
    {
        $config = [
            'certdir' => sys_get_temp_dir(),
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        $kid = FingerprintGenerator::forString(self::$pkGeneratePublic);

        $jwk = JWKFactory::createFromKey(self::$pkGeneratePublic, null, [
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
        ]);
        $JWKSet = new JWKSet([$jwk]);

        $jsonWebKeySetService = new JsonWebKeySetService(new ModuleConfig());

        $this->assertEquals($JWKSet->all(), $jsonWebKeySetService->protocolKeys());
    }

    /**
     * @throws \SimpleSAML\Error\Exception
     */
    public function testCertificationFileNotFound(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/OIDC protocol public key file does not exists/');

        $config = [
            'certdir' => __DIR__,
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        new JsonWebKeySetService(new ModuleConfig());
    }
}
