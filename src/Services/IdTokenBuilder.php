<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClaimSetInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
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
        protected readonly SubjectResolver $subjectResolver,
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
        if (!$userEntity instanceof ClaimSetInterface) {
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

        // The subject is the one the access token was minted with (SubjectResolver, once per mint), so the ID token
        // and the access token issued together name the End-User the same way, whatever `add_claims_to_id_token` or
        // the granted scopes say; on a refresh it is the subject carried since the original authentication (OpenID
        // Connect Core 1.0 section 12.2). It is relied upon elsewhere, e.g. when matching an `id_token_hint` (see
        // AuthenticationService::subjectMatchesAttributes()) and in logout token association. An access token
        // built without one (rehydrated from storage) has it resolved here by the same rule.
        $subject = $accessToken->getSubject() ?? $this->subjectResolver->resolve($userEntity);

        // Leave out only what is absent: a nonce or acr of "0" is a value the client sent or the source asserted.
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
        ], fn(mixed $value): bool => $value !== null && $value !== '');

        // The rest of the 'openid' claim set is the configured identity claims (ModuleConfig::getIdentityClaims()),
        // which identify the End-User next to 'sub' and go wherever it goes: placed like 'sub', whatever the
        // client's claim-release setting below says, and kept for a falsy value (no filter) for the same reason.
        $openIdClaims = $this->claimExtractor->extract(['openid'], $userEntity->getClaims());
        foreach ($openIdClaims as $claimName => $claimValue) {
            if (is_string($claimName) && $claimName !== '' && $claimName !== ClaimsEnum::Sub->value) {
                /** @psalm-suppress MixedAssignment */
                $payload[$claimName] = $claimValue;
            }
        }

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

        // The subject is written last: it is REQUIRED, and it must not be overwritten by the 'sub' the 'openid'
        // scope releases just above, which is resolved from the attributes as they are now rather than carried
        // from the mint.
        $payload[ClaimsEnum::Sub->value] = $this->core->helpers()->type()->ensureNonEmptyString($subject);

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

        return $this->core->helpers()->base64Url()->encode(
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
