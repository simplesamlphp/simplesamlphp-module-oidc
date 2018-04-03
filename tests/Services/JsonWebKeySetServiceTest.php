<?php
/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Services;

use Jose\Factory\JWKFactory;
use Jose\Object\JWKSet;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Modules\OpenIDConnect\Services\JsonWebKeySetService;

class JsonWebKeySetServiceTest extends TestCase
{
    /**
     * @var string
     */
    private static $pkGeneratePublic;

    public static function setUpBeforeClass()
    {
        // From https://www.andrewzammit.com/blog/php-openssl-rsa-shared-key-generation/
        $pkGenerate = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        // get the private key
        openssl_pkey_export($pkGenerate,$pkGeneratePrivate);

        // get the public key
        $pkGenerateDetails = openssl_pkey_get_details($pkGenerate);
        self::$pkGeneratePublic = $pkGenerateDetails['key'];

        // free resources
        openssl_pkey_free($pkGenerate);

        file_put_contents(sys_get_temp_dir()."/oidc_module.crt", self::$pkGeneratePublic);
    }

    public static function tearDownAfterClass()
    {
        unlink(sys_get_temp_dir()."/oidc_module.crt");
    }

    public function testKeys()
    {
        $config = [
            'certdir' => sys_get_temp_dir(),
        ];
        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');

        $jwk = JWKFactory::createFromKey(self::$pkGeneratePublic, null, [
            'use' => 'sig',
            'alg' => 'RS256',
        ]);
        $JWKSet = new JWKSet();
        $JWKSet->addKey($jwk);

        $jsonWebKeySetService = new JsonWebKeySetService();

        $this->assertEquals($JWKSet->getKeys(), $jsonWebKeySetService->keys());
    }

    /**
     * @expectedException \SimpleSAML_Error_Error
     */
    public function testCertificationFileNotFound()
    {
        $config = [
            'certdir' => __DIR__,
        ];
        \SimpleSAML_Configuration::loadFromArray($config, '', 'simplesaml');

        new JsonWebKeySetService();
    }
}
