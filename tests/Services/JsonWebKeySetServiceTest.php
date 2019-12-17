<?php

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

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Services;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;

class JsonWebKeySetServiceTest extends TestCase
{
    /**
     * @var string
     */
    private static $pkGeneratePublic;


    /**
     * @return void
     */
    public static function setUpBeforeClass()
    {
        // From https://www.andrewzammit.com/blog/php-openssl-rsa-shared-key-generation/
        $pkGenerate = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        // get the private key
        openssl_pkey_export($pkGenerate, $pkGeneratePrivate);

        // get the public key
        $pkGenerateDetails = openssl_pkey_get_details($pkGenerate);
        self::$pkGeneratePublic = $pkGenerateDetails['key'];

        // free resources
        openssl_pkey_free($pkGenerate);

        file_put_contents(sys_get_temp_dir().'/oidc_module.crt', self::$pkGeneratePublic);
    }


    /**
     * @return void
     */
    public static function tearDownAfterClass()
    {
        unlink(sys_get_temp_dir().'/oidc_module.crt');
    }


    /**
     * @return void
     */
    public function testKeys()
    {
        $config = [
            'certdir' => sys_get_temp_dir(),
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        $jwk = JWKFactory::createFromKey(self::$pkGeneratePublic, null, [
            'kid' => 'oidc',
            'use' => 'sig',
            'alg' => 'RS256',
        ]);
        $JWKSet = new JWKSet([$jwk]);

        $jsonWebKeySetService = new JsonWebKeySetService();

        $this->assertEquals($JWKSet->all(), $jsonWebKeySetService->keys());
    }


    /**
     * @expectedException \Exception
     * @return void
     */
    public function testCertificationFileNotFound()
    {
        $config = [
            'certdir' => __DIR__,
        ];
        Configuration::loadFromArray($config, '', 'simplesaml');

        new JsonWebKeySetService();
    }
}
