<?php

namespace SimpleSAML\Module\oidc\Services;

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;
use SimpleSAML\Module\oidc\Utils\UniqueIdentifierGenerator;

class JsonWebTokenBuilderService
{
    protected ConfigurationService $configurationService;
    protected Configuration $jwtConfig;

    public function __construct(
        ?ConfigurationService $configurationService = null
    ) {
        $this->configurationService = $configurationService ?? new ConfigurationService();

        $this->jwtConfig = Configuration::forAsymmetricSigner(
            $this->configurationService->getSigner(),
            InMemory::file(
                $this->configurationService->getPrivateKeyPath(),
                $this->configurationService->getPrivateKeyPassPhrase() ?? ''
            ),
            InMemory::empty()
        );
    }

    public function getDefaultJwtTokenBuilder(): Builder
    {
        // Ignore microseconds when handling dates.
        return $this->jwtConfig->builder(ChainedFormatter::withUnixTimestampDates())
            ->issuedBy($this->configurationService->getSimpleSAMLSelfURLHost())
            ->issuedAt(new DateTimeImmutable('now'))
            ->identifiedBy(UniqueIdentifierGenerator::hitMe());
    }

    public function getSignedJwtTokenFromBuilder(Builder $builder): UnencryptedToken
    {
        $kid = FingerprintGenerator::forFile($this->configurationService->getCertPath());

        return $builder->withHeader('kid', $kid)
            ->getToken(
                $this->jwtConfig->signer(),
                $this->jwtConfig->signingKey()
            );
    }

    public function getSigner(): Signer
    {
        return $this->configurationService->getSigner();
    }
}
