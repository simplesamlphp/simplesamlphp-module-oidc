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
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;

class JsonWebTokenBuilderService
{
    protected Configuration $jwtConfig;

    /**
     * @throws ReflectionException
     * @throws Exception
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
    }

    /**
     * @throws OAuthServerException
     */
    public function getDefaultJwtTokenBuilder(): Builder
    {
        // Ignore microseconds when handling dates.
        return $this->jwtConfig->builder(ChainedFormatter::withUnixTimestampDates())
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
