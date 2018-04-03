<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use Jose\Factory\JWKFactory;
use Jose\Object\JWKSet;
use SimpleSAML\Utils\Config;

class JsonWebKeySetService
{
    /**
     * @var JWKSet
     */
    private $jwkSet;

    public function __construct()
    {
        $publicKeyPath = Config::getCertPath('oidc_module.crt');

        if (!file_exists($publicKeyPath)) {
            throw new \SimpleSAML_Error_Error("OpenId Connect certification file does not exists: {$publicKeyPath}.");
        }

        $jwk = JWKFactory::createFromKeyFile($publicKeyPath, null, [
            'use' => 'sig',
            'alg' => 'RS256',
        ]);

        $this->jwkSet = new JWKSet();
        $this->jwkSet->addKey($jwk);
    }

    public function keys()
    {
        return $this->jwkSet->getKeys();
    }
}
