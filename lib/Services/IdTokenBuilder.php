<?php

namespace SimpleSAML\Module\oidc\Services;

use Base64Url\Base64Url;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use OpenIDConnectServer\Entities\ClaimSetInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entity\Interfaces\EntityStringRepresentationInterface;

class IdTokenBuilder
{
    /**
     * @var ClaimTranslatorExtractor
     */
    private $claimExtractor;
    /**
     * @var JsonWebTokenBuilderService
     */
    private $jsonWebTokenBuilderService;

    public function __construct(
        JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        ClaimTranslatorExtractor $claimExtractor
    ) {
        $this->jsonWebTokenBuilderService = $jsonWebTokenBuilderService;
        $this->claimExtractor = $claimExtractor;
    }

    public function build(
        UserEntityInterface $userEntity,
        AccessTokenEntity $accessToken,
        bool $addClaimsFromScopes,
        bool $addAccessTokenHash,
        ?string $nonce,
        ?int $authTime,
        ?string $acr,
        ?string $sessionId
    ) {
        if (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        // Add required id_token claims
        $builder = $this->getBuilder($accessToken, $userEntity);

        if (null !== $nonce) {
            $builder->withClaim('nonce', $nonce);
        }

        if (null !== $authTime) {
            $builder->withClaim('auth_time', $authTime);
        }

        if ($addAccessTokenHash) {
            $builder->withClaim(
                'at_hash',
                $this->generateAccessTokenHash(
                    $accessToken,
                    $this->jsonWebTokenBuilderService->getSigner()->algorithmId()
                )
            );
        }

        if (null !== $acr) {
            $builder->withClaim('acr', $acr);
        }

        if (null !== $sessionId) {
            $builder->withClaim('sid', $sessionId);
        }

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimExtractor->extractAdditionalIdTokenClaims(
            $requestedClaims,
            $userEntity->getClaims()
        );
        $claims = array_merge($additionalClaims, $claims);


        foreach ($claims as $claimName => $claimValue) {
            switch ($claimName) {
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor($claimValue);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(new DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ID:
                    $builder->identifiedBy($claimValue);
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(new DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($claimValue);
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@' . $claimValue));
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder->relatedTo($claimValue);
                    break;
                default:
                    if ($addClaimsFromScopes || array_key_exists($claimName, $additionalClaims)) {
                        $builder->withClaim($claimName, $claimValue);
                    }
            }
        }

        return $this->jsonWebTokenBuilderService->getSignedJwtTokenFromBuilder($builder);
    }

    protected function getBuilder(
        AccessTokenEntityInterface $accessToken,
        UserEntityInterface $userEntity
    ): Builder {
        return $this->jsonWebTokenBuilderService
            ->getDefaultJwtTokenBuilder()
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier())
            ->canOnlyBeUsedAfter(new DateTimeImmutable('now'))
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo($userEntity->getIdentifier());
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
            throw new RuntimeException(sprintf('JWS algorithm not supported (%s)', $jwsAlgorithm));
        }

        if ($accessToken instanceof EntityStringRepresentationInterface === false) {
            throw new RuntimeException('AccessTokenEntity must implement ' .
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
