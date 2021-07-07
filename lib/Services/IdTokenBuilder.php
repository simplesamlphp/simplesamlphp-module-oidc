<?php

namespace SimpleSAML\Module\oidc\Services;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;

class IdTokenBuilder
{
    /**
     * @var IdentityProviderInterface
     */
    private $identityProvider;
    /**
     * @var ClaimExtractor
     */
    private $claimExtractor;
    /**
     * @var ConfigurationService
     */
    private $configurationService;
    /**
     * @var CryptKey
     */
    private $privateKey;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        ClaimExtractor $claimExtractor,
        ConfigurationService $configurationService,
        CryptKey $privateKey
    ) {
        $this->identityProvider = $identityProvider;
        $this->claimExtractor = $claimExtractor;
        $this->configurationService = $configurationService;
        $this->privateKey = $privateKey;
    }

    public function build(AccessTokenEntityInterface $accessToken, ?string $nonce, ?int $authTime)
    {
        /** @var UserEntityInterface $userEntity */
        $userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

        if (false === is_a($userEntity, UserEntityInterface::class)) {
            throw new \RuntimeException('UserEntity must implement UserEntityInterface');
        } elseif (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new \RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        $jwtConfig = Configuration::forAsymmetricSigner(
            $this->configurationService->getSigner(),
            InMemory::plainText($this->privateKey->getKeyPath(), $this->privateKey->getPassPhrase() ?? ''),
            // The public key is not needed for signing
            InMemory::empty()
        );

        // Add required id_token claims
        $builder = $this->getBuilder($jwtConfig, $accessToken, $userEntity);

        if (null !== $nonce) {
            $builder->withClaim('nonce', $nonce);
        }

        if (null !== $authTime) {
            $builder->withClaim('auth_time', $authTime);
        }

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

        // Per https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4 certain claims
        // should only be added in certain scenarios. Allow deployer to control this.
        $addClaimsFromScopesToIdToken = $this->configurationService
            ->getOpenIDConnectConfiguration()
            ->getBoolean('alwaysAddClaimsToIdToken', true);

        foreach ($claims as $claimName => $claimValue) {
            switch ($claimName) {
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor($claimValue);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ID:
                    $builder->identifiedBy($claimValue);
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($claimValue);
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    $builder->canOnlyBeUsedAfter(new \DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder->relatedTo($claimValue);
                    break;
                default:
                    if ($addClaimsFromScopesToIdToken) {
                        $builder->withClaim($claimName, $claimValue);
                    }
            }
        }

        $kid = FingerprintGenerator::forFile($this->configurationService->getCertPath());

        return $builder->withHeader('kid', $kid)
            ->getToken(
                $jwtConfig->signer(),
                $jwtConfig->signingKey()
            );
    }

    protected function getBuilder(
        Configuration $jwtConfig,
        AccessTokenEntityInterface $accessToken,
        UserEntityInterface $userEntity
    ) {
        // Ignore microseconds when handling dates.
        return $jwtConfig->builder(ChainedFormatter::withUnixTimestampDates())
            ->issuedBy($this->configurationService->getSimpleSAMLSelfURLHost())
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier())
            ->canOnlyBeUsedAfter(new \DateTimeImmutable('now'))
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($userEntity->getIdentifier())
            ->issuedAt(new \DateTimeImmutable('now'));
    }
}
