<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Base64Url\Base64Url;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\IdToken;

class IdTokenBuilder
{
    public function __construct(
        protected readonly ClaimTranslatorExtractor $claimExtractor,
        protected readonly Core $core,
        protected readonly ModuleConfig $moduleConfig,
    ) {
    }

    /**
     * @psalm-suppress MixedAssignment
     */
    public function buildFor(
        UserEntityInterface $userEntity,
        AccessTokenEntity $accessToken,
        bool $addClaimsFromScopes,
        bool $addAccessTokenHash,
        ?string $nonce,
        ?int $authTime,
        ?string $acr,
        ?string $sessionId,
    ): IdToken {
        if (!is_a($userEntity, ClaimSetInterface::class)) {
            throw new RuntimeException('UserEntity must implement ClaimSetInterface');
        }

        $client = $accessToken->getClient();
        if (! $client instanceof ClientEntity) {
            throw new RuntimeException('Client is expected to be instance of ' . ClientEntity::class);
        }

        $protocolSignatureKeyPairBag = $this->moduleConfig->getProtocolSignatureKeyPairBag();
        $protocolSignatureKeyPair = $protocolSignatureKeyPairBag->getFirstOrFail();

        // ID Token signing algorithm that the client wants.
        $clientIdTokenSignedResponseAlg = $client->getIdTokenSignedResponseAlg();

        if (is_string($clientIdTokenSignedResponseAlg)) {
            $protocolSignatureKeyPair = $protocolSignatureKeyPairBag->getFirstByAlgorithmOrFail(
                SignatureAlgorithmEnum::from($clientIdTokenSignedResponseAlg),
            );
        }

        $currentTimestamp = $this->core->helpers()->dateTime()->getUtc()->getTimestamp();

        // Resolve the canonical subject identifier for this user. The subject is the user identifier, unless a `sub`
        // claim mapping (openid scope) produces a value, which then takes precedence. This is resolved up front, and
        // independently of the claim-release settings below, so that the issued `sub` is stable for a given user
        // across flows and clients (it must not vary with `add_claims_to_id_token` or the granted scopes): the `sub`
        // is the End-User's identity towards the client and is relied upon elsewhere, e.g. when matching an
        // `id_token_hint` (see AuthenticationService::subjectMatchesAttributes()) and in logout token association.
        $openIdClaims = $this->claimExtractor->extract(['openid'], $userEntity->getClaims());
        $subject = (isset($openIdClaims['sub']) && is_scalar($openIdClaims['sub'])) ?
        (string)$openIdClaims['sub'] :
        $userEntity->getIdentifier();

        $payload = array_filter([
            ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Iat->value => $currentTimestamp,
            ClaimsEnum::Jti->value => $this->core->helpers()->random()->string(),
            ClaimsEnum::Aud->value => $client->getIdentifier(),
            ClaimsEnum::Nbf->value => $currentTimestamp,
            ClaimsEnum::Exp->value => $accessToken->getExpiryDateTime()->getTimestamp(),
            ClaimsEnum::Nonce->value => $nonce,
            ClaimsEnum::AuthTime->value => $authTime,
            ClaimsEnum::ATHash->value => $addAccessTokenHash ?
                $this->generateAccessTokenHash(
                    $accessToken,
                    $protocolSignatureKeyPair->getSignatureAlgorithm()->value,
                ) :
                null,
            ClaimsEnum::Acr->value => $acr,
            ClaimsEnum::Sid->value => $sessionId,
        ]);

        // The subject is set after the optional claims above have been filtered, since it is REQUIRED and must be
        // kept even for a value that array_filter() would consider falsy (for example the valid subject "0").
        $payload[ClaimsEnum::Sub->value] = $this->core->helpers()->type()->ensureNonEmptyString($subject);

        // Reduce the number of claims by provided scope.
        $claims = $this->claimExtractor->extract(
            $accessToken->getScopes(),
            $userEntity->getClaims(),
        );
        $requestedClaims =  $accessToken->getRequestedClaims();
        $additionalClaims = $this->claimExtractor->extractAdditionalIdTokenClaims(
            $requestedClaims,
            $userEntity->getClaims(),
        );
        $claims = array_merge($additionalClaims, $claims);

        foreach ($claims as $claimName => $claimValue) {
            if (
                is_string($claimName) &&
                $claimName !== '' &&
                ($addClaimsFromScopes || array_key_exists($claimName, $additionalClaims))
            ) {
                $payload[$claimName] = $claimValue;
            }
        }

        $header = [
            ClaimsEnum::Kid->value => $protocolSignatureKeyPair->getKeyPair()->getKeyId(),
        ];

        return $this->core->idTokenFactory()->fromData(
            $protocolSignatureKeyPair->getKeyPair()->getPrivateKey(),
            $protocolSignatureKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        );
    }

    /**
     * @param string $jwsAlgorithm JWS Algorithm designation (like RS256,
     * RS384...).
     */
    public function generateAccessTokenHash(AccessTokenEntityInterface $accessToken, string $jwsAlgorithm): string
    {
        if ($jwsAlgorithm === SignatureAlgorithmEnum::EdDSA->value) {
            $hashAlgorithm = 'sha512';
            $hashByteLength = 32; // 256 bits / 8
        } else {
            $validBitLengths = [256, 384, 512];

            $jwsAlgorithmBitLength = (int) substr($jwsAlgorithm, 2);

            if (!in_array($jwsAlgorithmBitLength, $validBitLengths, true)) {
                throw new RuntimeException(sprintf('JWS algorithm not supported (%s)', $jwsAlgorithm));
            }

            $hashAlgorithm = 'sha' . $jwsAlgorithmBitLength;
            $hashByteLength = $jwsAlgorithmBitLength / 2 / 8;
        }

        if ($accessToken instanceof EntityStringRepresentationInterface === false) {
            throw new RuntimeException('AccessTokenEntity must implement ' .
                                        EntityStringRepresentationInterface::class);
        }

        $accessTokenString = $accessToken->toString();

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
