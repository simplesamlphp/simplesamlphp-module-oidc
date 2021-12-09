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

namespace SimpleSAML\Module\oidc\Services;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Utils\Config;

class JsonWebKeySetService
{
    /**
     * @var JWKSet
     */
    private $jwkSet;

    public function __construct()
    {
        $publicKeyPath = (new Config())->getCertPath('oidc_module.crt');

        if (!file_exists($publicKeyPath)) {
            throw new Exception("OpenId Connect certification file does not exists: {$publicKeyPath}.");
        }

        $kid = FingerprintGenerator::forFile($publicKeyPath);

        $jwk = JWKFactory::createFromKeyFile($publicKeyPath, null, [
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
        ]);

        $this->jwkSet = new JWKSet([$jwk]);
    }

    /**
     * @return \Jose\Component\Core\JWK[]
     */
    public function keys()
    {
        return $this->jwkSet->all();
    }
}
