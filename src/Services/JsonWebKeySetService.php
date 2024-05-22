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
namespace SimpleSAML\Module\oidc\Services;

use Jose\Component\Console\PublicKeyCommand;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Codebooks\ClaimNamesEnum;
use SimpleSAML\Module\oidc\Codebooks\ClaimValues\PublicKeyUseEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;

class JsonWebKeySetService
{
    /** @var JWKSet JWKS for OIDC protocol. */
    private readonly JWKSet $protocolJwkSet;
    /** @var JWKSet|null JWKS for OpenID Federation. */
    private ?JWKSet $federationJwkSet = null;

    /**
     * @throws Exception
     * @throws \Exception
     */
    public function __construct(ModuleConfig $moduleConfig)
    {
        $publicKeyPath = $moduleConfig->getCertPath();
        if (!file_exists($publicKeyPath)) {
            throw new Exception("OIDC protocol public key file does not exists: $publicKeyPath.");
        }

        $jwk = JWKFactory::createFromKeyFile($publicKeyPath, null, [
            ClaimNamesEnum::KeyId->value => FingerprintGenerator::forFile($publicKeyPath),
            ClaimNamesEnum::PublicKeyUse->value => PublicKeyUseEnum::Signature->value,
            ClaimNamesEnum::Algorithm->value => $moduleConfig->getSigner()->algorithmId(),
        ]);

        $this->protocolJwkSet = new JWKSet([$jwk]);

        if (
            ($federationPublicKeyPath = $moduleConfig->getFederationCertPath()) &&
            file_exists($federationPublicKeyPath) &&
            ($federationSigner = $moduleConfig->getFederationSigner())
        ) {
            $federationJwk = JWKFactory::createFromKeyFile($federationPublicKeyPath, null, [
                ClaimNamesEnum::KeyId->value => FingerprintGenerator::forFile($federationPublicKeyPath),
                ClaimNamesEnum::PublicKeyUse->value => PublicKeyUseEnum::Signature->value,
                ClaimNamesEnum::Algorithm->value => $federationSigner->algorithmId(),
            ]);

            $this->federationJwkSet = new JWKSet([$federationJwk]);
        }
    }

    /**
     * @return JWK[]
     */
    public function protocolKeys(): array
    {
        return $this->protocolJwkSet->all();
    }

    /**
     * @throws OidcServerException
     */
    public function federationKeys(): array
    {
        if (is_null($this->federationJwkSet)) {
            throw OidcServerException::serverError('OpenID Federation public key not set.');
        }

        return $this->federationJwkSet->all();
    }
}
