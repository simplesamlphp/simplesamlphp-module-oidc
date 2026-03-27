<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Jws;

class NonceService
{
    public function __construct(
        protected readonly Jws $jws,
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \Exception
     */
    public function generateNonce(): string
    {
        $signatureKeyPair = $this->moduleConfig->getVciSignatureKeyPairBag()->getFirstOrFail();
        $currentTimestamp = $this->jws->helpers()->dateTime()->getUtc()->getTimestamp();

        // Nonce is valid for 5 minutes (300 seconds)
        // TODO mivanci Consider making this configurable.
        $expiryTimestamp = $currentTimestamp + 300;

        $payload = [
            ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Iat->value => $currentTimestamp,
            ClaimsEnum::Exp->value => $expiryTimestamp,
            'nonce_val' => bin2hex(random_bytes(16)),
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

            // Verify signature
            $signatureKeyPair = $this->moduleConfig->getVciSignatureKeyPairBag()->getFirstOrFail();
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
        } catch (\Exception $e) {
            $this->loggerService->warning('Nonce validation failed: ' . $e->getMessage());
            return false;
        }
    }
}
