<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Base64Url\Base64Url;
use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;

class IdTokenBuilder
{
    public function __construct(
        private readonly JsonWebTokenBuilderService $jsonWebTokenBuilderService,
        private readonly ClaimTranslatorExtractor $claimExtractor,
    ) {
    }

    /**
     * @throws Exception
     * @psalm-suppress ArgumentTypeCoercion
     */
    public function build(
        UserEntityInterface $userEntity,
        AccessTokenEntity $accessToken,
        bool $addClaimsFromScopes,
        bool $addAccessTokenHash,
        ?string $nonce,
        ?int $authTime,
        ?string $acr,
        ?string $sessionId,
    ): UnencryptedToken {
        if (false === is_a($userEntity, ClaimSetInterface::class)) {
            throw new RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        // Add required id_token claims
        $builder = $this->getBuilder($accessToken, $userEntity);

        if (null !== $nonce) {
            $builder = $builder->withClaim('nonce', $nonce);
        }

        if (null !== $authTime) {
            $builder = $builder->withClaim('auth_time', $authTime);
        }

        if ($addAccessTokenHash) {
            $builder = $builder->withClaim(
                'at_hash',
                $this->generateAccessTokenHash(
                    $accessToken,
                    $this->jsonWebTokenBuilderService->getSigner()->algorithmId(),
                ),
            );
        }

        if (null !== $acr) {
            $builder = $builder->withClaim('acr', $acr);
        }

        if (null !== $sessionId) {
            $builder = $builder->withClaim('sid', $sessionId);
        }

        // Need a claim factory here to reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract($accessToken->getScopes(), $userEntity->getClaims());
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimExtractor->extractAdditionalIdTokenClaims(
            $requestedClaims,
            $userEntity->getClaims(),
        );
        $claims = array_merge($additionalClaims, $claims);

        /**
         * @var string $claimName
         * @var  mixed $claimValue
         */
        foreach ($claims as $claimName => $claimValue) {
            switch ($claimName) {
                case RegisteredClaims::AUDIENCE:
                    if (is_array($claimValue)) {
                        /** @psalm-suppress MixedAssignment */
                        foreach ($claimValue as $aud) {
                            $builder = $builder->permittedFor((string)$aud);
                        }
                    } else {
                        $builder = $builder->permittedFor((string)$claimValue);
                    }
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    /** @noinspection PhpUnnecessaryStringCastInspection */
                    $builder = $builder->expiresAt(new DateTimeImmutable('@' . (string)$claimValue));
                    break;
                case RegisteredClaims::ID:
                    $builder = $builder->identifiedBy((string)$claimValue);
                    break;
                case RegisteredClaims::ISSUED_AT:
                    /** @noinspection PhpUnnecessaryStringCastInspection */
                    $builder = $builder->issuedAt(new DateTimeImmutable('@' . (string)$claimValue));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder = $builder->issuedBy((string)$claimValue);
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    /** @noinspection PhpUnnecessaryStringCastInspection */
                    $builder = $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@' . (string)$claimValue));
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder = $builder->relatedTo((string)$claimValue);
                    break;
                default:
                    if ($addClaimsFromScopes || array_key_exists($claimName, $additionalClaims)) {
                        $builder = $builder->withClaim($claimName, $claimValue);
                    }
            }
        }

        return $this->jsonWebTokenBuilderService->getSignedJwtTokenFromBuilder($builder);
    }

    /**
     * @throws OAuthServerException
     */
    protected function getBuilder(
        AccessTokenEntityInterface $accessToken,
        UserEntityInterface $userEntity,
    ): Builder {
        /** @psalm-suppress ArgumentTypeCoercion */
        return $this->jsonWebTokenBuilderService
            ->getDefaultJwtTokenBuilder()
            ->permittedFor($accessToken->getClient()->getIdentifier())
            ->identifiedBy($accessToken->getIdentifier())
            ->canOnlyBeUsedAfter(new DateTimeImmutable('now'))
            ->expiresAt($accessToken->getExpiryDateTime())
            ->relatedTo((string)$userEntity->getIdentifier());
    }

    /**
     * @param string $jwsAlgorithm JWS Algorithm designation (like RS256, RS384...)
     */
    protected function generateAccessTokenHash(AccessTokenEntityInterface $accessToken, string $jwsAlgorithm): string
    {
        $validBitLengths = [256, 384, 512];

        $jwsAlgorithmBitLength = (int) substr($jwsAlgorithm, 2);

        if (!in_array($jwsAlgorithmBitLength, $validBitLengths, true)) {
            throw new RuntimeException(sprintf('JWS algorithm not supported (%s)', $jwsAlgorithm));
        }

        if ($accessToken instanceof EntityStringRepresentationInterface === false) {
            throw new RuntimeException('AccessTokenEntity must implement ' .
                                        EntityStringRepresentationInterface::class);
        }

        // Try to use toString() so that it uses the string representation if it was already cast to string,
        // otherwise, use the cast version.
        $accessTokenString = $accessToken->toString() ?? (string) $accessToken;

        $hashAlgorithm = 'sha' . $jwsAlgorithmBitLength;

        $hashByteLength = $jwsAlgorithmBitLength / 2 / 8;

        return Base64Url::encode(
            substr(
                hash(
                    $hashAlgorithm,
                    $accessTokenString,
                    true,
                ),
                0,
                $hashByteLength,
            ),
        );
    }
}
