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

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use SimpleSAML\Error;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\PublicKeyUseEnum;

class JsonWebKeySetService
{
    /** @var JWKSet JWKS for OIDC protocol. */
    protected JWKSet $protocolJwkSet;
    /** @var JWKSet|null JWKS for OpenID Federation. */
    protected ?JWKSet $federationJwkSet = null;

    /**
     * @throws \SimpleSAML\Error\Exception
     * @throws \Exception
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
    ) {
        $this->prepareProtocolJwkSet();

        $this->prepareFederationJwkSet();
    }

    /**
     * @return \Jose\Component\Core\JWK[]
     */
    public function protocolKeys(): array
    {
        return $this->protocolJwkSet->all();
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function federationKeys(): array
    {
        if (is_null($this->federationJwkSet)) {
            throw OidcServerException::serverError('OpenID Federation public key not set.');
        }

        return $this->federationJwkSet->all();
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\Exception
     */
    protected function prepareProtocolJwkSet(): void
    {
        $protocolPublicKeyPath = $this->moduleConfig->getProtocolCertPath();

        if (!file_exists($protocolPublicKeyPath)) {
            throw new Error\Exception("OIDC protocol public key file does not exists: $protocolPublicKeyPath.");
        }

        $jwk = JWKFactory::createFromKeyFile($protocolPublicKeyPath, null, [
            //ClaimsEnum::Kid->value => FingerprintGenerator::forFile($protocolPublicKeyPath),
            ClaimsEnum::Kid->value => '4fdbd515cda5cc0d2fc2f1124a1a3dc995741037bbd87451dc78fcd3251e025a',
            ClaimsEnum::Use->value => PublicKeyUseEnum::Signature->value,
            ClaimsEnum::Alg->value => $this->moduleConfig->getProtocolSigner()->algorithmId(),
        ]);

        $keys = [$jwk];

        if (
            ($protocolNewPublicKeyPath = $this->moduleConfig->getProtocolNewCertPath()) &&
            file_exists($protocolNewPublicKeyPath)
        ) {
            $newJwk = JWKFactory::createFromKeyFile($protocolNewPublicKeyPath, null, [
                ClaimsEnum::Use->value => PublicKeyUseEnum::Signature->value,
                //ClaimsEnum::Kid->value => FingerprintGenerator::forFile($protocolNewPublicKeyPath),

                ClaimsEnum::Kid->value => '4fdbd515cda5cc0d2fc2f1124a1a3dc995741037bbd87451dc78fcd3251e025a',
                ClaimsEnum::Alg->value => $this->moduleConfig->getProtocolSigner()->algorithmId(),
            ]);

            $keys[] = $newJwk;
        }

        $this->protocolJwkSet = new JWKSet($keys);
    }

    protected function prepareFederationJwkSet(): void
    {
        $federationPublicKeyPath = $this->moduleConfig->getFederationCertPath();

        if (!file_exists($federationPublicKeyPath)) {
            return;
        }

        $federationJwk = JWKFactory::createFromKeyFile($federationPublicKeyPath, null, [
            //ClaimsEnum::Kid->value => FingerprintGenerator::forFile($federationPublicKeyPath),

            ClaimsEnum::Kid->value => '4fdbd515cda5cc0d2fc2f1124a1a3dc995741037bbd87451dc78fcd3251e025a',
            ClaimsEnum::Use->value => PublicKeyUseEnum::Signature->value,
            ClaimsEnum::Alg->value => $this->moduleConfig->getFederationSigner()->algorithmId(),
        ]);

        $keys = [$federationJwk];

        if (
            ($federationNewPublicKeyPath = $this->moduleConfig->getFederationNewCertPath()) &&
            file_exists($federationNewPublicKeyPath)
        ) {
            $federationNewJwk = JWKFactory::createFromKeyFile($federationNewPublicKeyPath, null, [
                ClaimsEnum::Kid->value => FingerprintGenerator::forFile($federationNewPublicKeyPath),
                ClaimsEnum::Use->value => PublicKeyUseEnum::Signature->value,
                ClaimsEnum::Alg->value => $this->moduleConfig->getFederationSigner()->algorithmId(),
            ]);

            $keys[] = $federationNewJwk;
        }

        $this->federationJwkSet = new JWKSet($keys);
    }
}
