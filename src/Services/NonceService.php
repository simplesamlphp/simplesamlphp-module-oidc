<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

class NonceService
{
    public function __construct(
        protected readonly Jws $jws,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
        protected readonly Helpers $helpers,
    ) {
    }


    /**
     * @throws \Exception
     */
    public function generateNonce(): string
    {
        $signatureKeyPair = $this->moduleConfig->getActiveVciSignatureKeyPair();
        $currentDateTime = $this->jws->helpers()->dateTime()->getUtc();
        $currentTimestamp = $currentDateTime->getTimestamp();

        // Nonce is valid for the configured TTL (defaults to 5 minutes).
        $expiryTimestamp = $currentDateTime->add($this->moduleConfig->getVciNonceTtl())->getTimestamp();

        $payload = [
            ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Iat->value => $currentTimestamp,
            ClaimsEnum::Exp->value => $expiryTimestamp,
            ClaimsEnum::NonceVal->value => $this->helpers->random()->getIdentifier(16),
        ];

        $header = [
            ClaimsEnum::Kid->value => $signatureKeyPair->getKeyPair()->getKeyId(),
        ];

        return $this->jws->parsedJwsFactory()->fromData(
            $signatureKeyPair->getKeyPair()->getPrivateKey(),
            $signatureKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        )->getToken();
    }


    public function validateNonce(string $nonce): bool
    {
        try {
            $parsedJws = $this->jws->parsedJwsFactory()->fromToken($nonce);

            // Verify signature, against the key the nonce names rather than against whichever key is
            // signing now. A nonce handed out shortly before a key rollover is otherwise rejected for
            // the remainder of its lifetime, which reads to a wallet as the issuer refusing its proof.
            $signatureKeyPair = $this->resolveVerificationKeyPair($parsedJws->getKeyId());
            $parsedJws->verifyWithKey($signatureKeyPair->getKeyPair()->getPublicKey()->jwk()->all());

            // Verify issuer
            if ($parsedJws->getIssuer() !== $this->moduleConfig->getIssuer()) {
                $this->loggerService->warning('Nonce validation failed: invalid issuer.');
                return false;
            }

            // Verify expiration. This is also done in the JWS factory class.
            $currentTimestamp = $this->jws->helpers()->dateTime()->getUtc()->getTimestamp();
            if ($parsedJws->getExpirationTime() < $currentTimestamp) {
                $this->loggerService->warning('Nonce validation failed: expired.');
                return false;
            }

            $this->loggerService->debug('Nonce validation succeeded.');
            return true;
        } catch (Exception $e) {
            $this->loggerService->warning('Nonce validation failed: ' . $e->getMessage());
            return false;
        }
    }


    /**
     * The key a nonce says it was signed with.
     *
     * Every candidate is one of this issuer's own configured key pairs, so honouring the `kid` is no
     * weaker than always using the active one: naming a key is not the same as being able to sign with
     * it. A nonce carrying no `kid` at all predates nothing this module issues, but is still checked
     * against the active key rather than rejected outright.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException When the named key is not configured, which
     * means this issuer either never signed the nonce or no longer retains the key that did.
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function resolveVerificationKeyPair(?string $keyId): SignatureKeyPair
    {
        if ($keyId === null) {
            return $this->moduleConfig->getActiveVciSignatureKeyPair();
        }

        return $this->moduleConfig->getVciSignatureKeyPairBag()->getByKeyId($keyId) ??
        throw new OpenIdException(
            sprintf(
                'the signing key "%s" it names is not configured for Verifiable Credential Issuance.',
                $keyId,
            ),
        );
    }
}
