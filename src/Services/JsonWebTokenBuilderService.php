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
use ReflectionException;
use SimpleSAML\Module\oidc\Codebooks\ClaimNamesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;

class JsonWebTokenBuilderService
{
    /**
     * @var Configuration Token configuration related to OIDC protocol.
     */
    protected Configuration $protocolJwtConfig;

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
        protected ModuleConfig $moduleConfig = new ModuleConfig(),
    ) {
        $this->protocolJwtConfig = Configuration::forAsymmetricSigner(
            $this->moduleConfig->getProtocolSigner(),
            InMemory::file(
                $this->moduleConfig->getProtocolPrivateKeyPath(),
                $this->moduleConfig->getProtocolPrivateKeyPassPhrase() ?? ''
            ),
            InMemory::plainText('empty', 'empty')
        );

        // According to OpenID Federation specification, we need to use different signing keys for federation related
        // functions. Since we won't force OP implementor to enable federation support, this part is optional.
        if (
            ($federationSigner = $this->moduleConfig->getFederationSigner()) &&
            ($federationPrivateKeyPath = $this->moduleConfig->getFederationPrivateKeyPath()) &&
            file_exists($federationPrivateKeyPath)
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
     * Get JWT Builder which uses OIDC protocol related signing configuration.
     *
     * @throws OidcServerException
     */
    public function getProtocolJwtBuilder(): Builder
    {
        return $this->getDefaultJwtBuilder($this->protocolJwtConfig);
    }

    /**
     * Get JWT Builder which uses OpenID Federation related signing configuration.
     *
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
     * Get default JWT Builder by using the provided configuration, with predefined claims like iss, iat, jti.
     *
     * @throws OidcServerException
     */
    public function getDefaultJwtBuilder(Configuration $configuration): Builder
    {
        /** @psalm-suppress ArgumentTypeCoercion */
        // Ignore microseconds when handling dates.
        return $configuration->builder(ChainedFormatter::withUnixTimestampDates())
            ->issuedBy($this->moduleConfig->getIssuer())
            ->issuedAt(new DateTimeImmutable('now'))
            ->identifiedBy(UniqueIdentifierGenerator::hitMe());
    }

    /**
     * Get signed JWT using the OIDC protocol JWT signing configuration.
     *
     * @throws Exception
     */
    public function getSignedProtocolJwt(Builder $builder): UnencryptedToken
    {
        $headers = [
            ClaimNamesEnum::KeyId->value => FingerprintGenerator::forFile($this->moduleConfig->getProtocolCertPath()),
        ];

        return $this->getSignedJwt($builder, $this->protocolJwtConfig, $headers);
    }

    /**
     * Get signed JWT using the OpenID Federation JWT signing configuration.
     *
     * @throws OidcServerException
     */
    public function getSignedFederationJwt(Builder $builder): UnencryptedToken
    {
        if (is_null($federationCertPath = $this->moduleConfig->getFederationCertPath())) {
            throw OidcServerException::serverError('Federation certificate path not set.');
        }

        $headers = [
            ClaimNamesEnum::KeyId->value => FingerprintGenerator::forFile($federationCertPath),
        ];

        return $this->getSignedJwt($builder, $this->protocolJwtConfig, $headers);
    }

    /**
     * Get signed JWT for provided builder and JWT signing configuration, and optionally with any additional headers to
     * include.
     */
    public function getSignedJwt(
        Builder $builder,
        Configuration $jwtConfig,
        array $headers = [],
    ): UnencryptedToken {
        /**
         * @var non-empty-string $headerKey
         * @psalm-suppress MixedAssignment
         */
        foreach ($headers as $headerKey => $headerValue) {
            $builder = $builder->withHeader($headerKey, $headerValue);
        }

        return $builder->getToken($jwtConfig->signer(), $jwtConfig->signingKey());
    }

    /**
     * @throws ReflectionException
     */
    public function getProtocolSigner(): Signer
    {
        return $this->moduleConfig->getProtocolSigner();
    }
}
