<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\Exception\OAuthServerException;
use ReflectionException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;

class JsonWebTokenBuilderService
{
    /**
     * @var Configuration Token configuration related to OIDC protocol.
     */
    protected Configuration $jwtConfig;

    /**
     * @var ?Configuration Token configuration related to OpenID Federation.
     */
    protected ?Configuration $federationJwtConfig = null;

    /**
     * @throws ReflectionException
     * @throws Exception
     *
     * @psalm-suppress ArgumentTypeCoercion
     */
    public function __construct(
        protected ModuleConfig $moduleConfig = new ModuleConfig()
    ) {
        $this->jwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfig->getSigner(),
            InMemory::file(
                $this->moduleConfig->getPrivateKeyPath(),
                $this->moduleConfig->getPrivateKeyPassPhrase() ?? ''
            ),
            InMemory::plainText('empty', 'empty')
        );

        if (
            ($federationSigner = $this->moduleConfig->getFederationSigner()) &&
            ($federationPrivateKeyPath = $this->moduleConfig->getFederationPrivateKeyPath())
        ) {
            $this->federationJwtConfig = Configuration::forAsymmetricSigner(
                $federationSigner,
                InMemory::file(
                    $federationPrivateKeyPath,
                    $this->moduleConfig->getFederationPrivateKeyPassPhrase() ?? ''
                ),
                InMemory::plainText('empty', 'empty')
            );
        }
    }

    /**
     * @throws OidcServerException
     */
    public function getProtocolJwtBuilder(): Builder
    {
        return $this->getDefaultJwtBuilder($this->jwtConfig);
    }

    /**
     * @throws OidcServerException
     */
    public function getFederationJwtBuilder(): Builder
    {
        if (is_null($this->federationJwtConfig)) {
            throw OidcServerException::serverError('Federation JWT PKI configuration is not set.');
        }

        return $this->getDefaultJwtBuilder($this->federationJwtConfig);
    }

    /**
     * @throws OidcServerException
     */
    public function getDefaultJwtBuilder(Configuration $configuration): Builder
    {
        /** @psalm-suppress ArgumentTypeCoercion */
        // Ignore microseconds when handling dates.
        return $configuration->builder(ChainedFormatter::withUnixTimestampDates())
            ->issuedBy($this->moduleConfig->getSimpleSAMLSelfURLHost())
            ->issuedAt(new DateTimeImmutable('now'))
            ->identifiedBy(UniqueIdentifierGenerator::hitMe());
    }

    /**
     * @throws Exception
     */
    public function getSignedJwtTokenFromBuilder(Builder $builder): UnencryptedToken
    {
        $kid = FingerprintGenerator::forFile($this->moduleConfig->getCertPath());

        return $builder->withHeader('kid', $kid)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );
    }

    /**
     * @throws ReflectionException
     */
    public function getSigner(): Signer
    {
        return $this->moduleConfig->getSigner();
    }
}
