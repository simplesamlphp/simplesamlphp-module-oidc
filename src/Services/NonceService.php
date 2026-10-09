<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use DateTimeImmutable;
use Exception;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\ParsedJws;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

class NonceService
{
    /**
     * The `typ` header every nonce carries, which nothing else this issuer signs carries (explicit typing, RFC
     * 8725 section 3.11).
     *
     * A nonce is signed with the Verifiable Credential Issuance key, the key this issuer's credentials and Status
     * List Tokens are signed with too, and both of those can name this issuer in `iss` and carry an `exp`. Told
     * apart by signature, issuer and expiry alone, a Status List Token fetched from its public endpoint, or a
     * `jwt_vc_json` credential, passes as a nonce, and keeps a key proof built on it fresh for as long as it lives
     * rather than for minutes.
     */
    final public const string TYPE = 'c-nonce+jwt';


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
            ClaimsEnum::Typ->value => self::TYPE,
        ];

        return $this->jws->parsedJwsFactory()->fromData(
            $signatureKeyPair->getKeyPair()->getPrivateKey(),
            $signatureKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        )->getToken();
    }


    /**
     * Whether the value is a nonce this issuer handed out and which has not expired: of the nonce type, signed with
     * one of this issuer's credential signing keys, naming this issuer, with a nonce value, and living no longer
     * than a nonce is given.
     */
    public function validateNonce(string $nonce): bool
    {
        try {
            $parsedJws = $this->jws->parsedJwsFactory()->fromToken($nonce);

            // Before the key is looked up: whatever else this issuer signed is refused here, without being
            // checked any further.
            if ($parsedJws->getType() !== self::TYPE) {
                $this->loggerService->warning('Nonce validation failed: not of the nonce type.');
                return false;
            }

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

            $nonceValue = $parsedJws->getPayloadClaim(ClaimsEnum::NonceVal->value);
            if (!is_string($nonceValue) || $nonceValue === '') {
                $this->loggerService->warning('Nonce validation failed: no nonce value.');
                return false;
            }

            // Verify expiration. This is also done in the JWS factory class. Read once: the accessor checks
            // the clock again on every call.
            $expirationTime = $parsedJws->getExpirationTime();
            $currentTimestamp = $this->jws->helpers()->dateTime()->getUtc()->getTimestamp();
            if ($expirationTime === null || $expirationTime < $currentTimestamp) {
                $this->loggerService->warning('Nonce validation failed: expired.');
                return false;
            }

            if (!$this->isLifetimeWithinNonceTtl($parsedJws, $expirationTime)) {
                $this->loggerService->warning('Nonce validation failed: lifetime longer than a nonce is given.');
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
     * Whether the nonce says it was issued, and was given no longer than the configured nonce lifetime: every
     * nonce generateNonce() signs is given exactly that.
     *
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException When the issue time lies ahead (the leeway allowing).
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     * @throws \Exception
     */
    protected function isLifetimeWithinNonceTtl(ParsedJws $parsedJws, int $expirationTime): bool
    {
        $issuedAt = $parsedJws->getIssuedAt();

        return $issuedAt !== null && $expirationTime <= $this->permittedExpirationTime($issuedAt);
    }


    /**
     * The latest expiry a nonce issued at the given time can have: the configured lifetime added to the issue
     * time in UTC, as generateNonce() adds it. Not the lifetime counted in seconds from now: in a PHP time zone
     * with daylight saving, a day before the change is 23 or 25 hours, and a month is as long as the current
     * one, so nonces generateNonce() had just signed would be refused.
     *
     * @throws \Exception
     */
    protected function permittedExpirationTime(int $issuedAt): int
    {
        return (new DateTimeImmutable('@' . $issuedAt))->add($this->moduleConfig->getVciNonceTtl())->getTimestamp();
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
