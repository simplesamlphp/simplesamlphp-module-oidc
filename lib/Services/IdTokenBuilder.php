<?php

namespace SimpleSAML\Module\oidc\Services;

use Base64Url\Base64Url;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\ClaimExtractor;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Utils\FingerprintGenerator;

class IdTokenBuilder
{
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
        ClaimExtractor $claimExtractor,
        ConfigurationService $configurationService,
        CryptKey $privateKey
    ) {
        $this->claimExtractor = $claimExtractor;
        $this->configurationService = $configurationService;
        $this->privateKey = $privateKey;
    }

    public function build(
        UserEntityInterface $userEntity,
        AccessTokenEntityInterface $accessToken,
        bool $addClaimsFromScopes,
        bool $addAccessTokenHash,
        ?string $nonce,
        ?int $authTime
    ) {
        if (false === is_a($userEntity, ClaimSetInterface::class)) {
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

        if ($addAccessTokenHash) {
            $builder->withClaim(
                'at_hash',
                $this->generateAccessTokenHash($accessToken, $jwtConfig->signer()->algorithmId())
            );
        }

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());

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
                    if ($addClaimsFromScopes) {
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

    /**
     * @param AccessTokenEntityInterface $accessToken
     * @param string $jwsAlgorithm JWS Algorithm designation (like RS256, RS384...)
     * @return string
     */
    protected function generateAccessTokenHash(AccessTokenEntityInterface $accessToken, string $jwsAlgorithm): string
    {
        $validBitLengths = [256, 384, 512];

        $jwsAlgorithmBitLength = (int) substr($jwsAlgorithm, 2);

        if (! in_array($jwsAlgorithmBitLength, $validBitLengths, true)) {
            throw new \RuntimeException(sprintf('JWS algorithm not supported (%s)', $jwsAlgorithm));
        }

        if ($accessToken instanceof EntityStringRepresentationInterface === false) {
            throw new \RuntimeException('AccessTokenEntity must implement ' .
                                        EntityStringRepresentationInterface::class);
        }

        // Try to use toString() so that it uses the string representation if it was already casted to string,
        // otherwise, use the casted version.
        $accessTokenString = $accessToken->toString() ?? (string) $accessToken;

        $hashAlgorithm = 'sha' . $jwsAlgorithmBitLength;

        $hashByteLength = (int) ($jwsAlgorithmBitLength / 2 / 8);

        return Base64Url::encode(
            substr(
                hash(
                    $hashAlgorithm,
                    $accessTokenString,
                    true
                ),
                0,
                $hashByteLength
            )
        );
    }
}
