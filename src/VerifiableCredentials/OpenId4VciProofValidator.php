<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use JsonException;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use Throwable;

/**
 * Decides whether a Credential Request may be issued against, and what its credentials are bound to.
 *
 * Every check here refuses the request. That is the point of the class: these checks used to live inline
 * in the credential endpoint, where a proof naming a key this issuer could not resolve fell through to a
 * warning and the credential was issued anyway - signature unverified, nonce unchecked, bound to a
 * subject identifier of this issuer's own making. A wallet could not tell that apart from a proof which
 * had been honoured.
 *
 * Validation is request-wide rather than proof by proof. A `proofs` array is validated to its last entry
 * before the caller issues anything, because issuing along the way would let a request whose final proof
 * is bad still spend the Status List entries its earlier proofs allocated, on credentials no wallet ever
 * receives.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\OpenId4VciProofValidatorTest
 */
class OpenId4VciProofValidator
{
    /**
     * The only Key Proof type this issuer accepts, and the only one its metadata advertises.
     */
    final public const string PROOF_TYPE_JWT = 'jwt';

    /**
     * JWK members which describe a key without being part of it, so they are acceptable whatever the
     * key type is.
     */
    protected const array COMMON_JWK_MEMBERS = [
        'kty',
        'kid',
        'alg',
        'use',
        'key_ops',
        'x5u',
        'x5c',
        'x5t',
        'x5t#S256',
    ];

    /**
     * The public members each accepted key type is made of.
     *
     * An allowlist, rather than a list of private members to reject, because the rejection has to hold
     * for a member nobody thought to list. OpenID4VCI forbids private key material in a `jwk` header,
     * and this module would otherwise embed whatever it was sent verbatim into the `did:jwk` it
     * synthesises for the credential's subject - publishing the wallet's private key inside a credential
     * the wallet itself asked for. Symmetric keys are absent deliberately: a shared secret proves
     * possession to nobody, so `oct` is not a key type a Key Proof can be built on.
     *
     * @var array<string,list<string>>
     */
    protected const array PUBLIC_JWK_MEMBERS_BY_KEY_TYPE = [
        'EC' => ['crv', 'x', 'y'],
        'RSA' => ['n', 'e'],
        'OKP' => ['crv', 'x'],
    ];


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly Did $did,
        protected readonly NonceService $nonceService,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * Validate everything a Credential Request says about holder binding.
     *
     * @param array<array-key,mixed> $requestData
     * @return list<?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof> One
     * entry per credential the request is to be issued, in the order the proofs arrived. A null entry
     * means an unbound credential, which only a proofless configuration produces.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException When the request is refused.
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \JsonException
     */
    public function validateRequest(
        array $requestData,
        VciCredentialBindingPolicyEnum $bindingPolicy,
        AccessTokenEntity $accessToken,
    ): array {
        if ($bindingPolicy === VciCredentialBindingPolicyEnum::Proofless) {
            $this->refuseSuppliedProofs($requestData);

            return [null];
        }

        $proofJwts = $this->extractProofJwts($requestData);

        $this->loggerService->debug(
            'Validating key proofs before issuing anything.',
            ['count' => count($proofJwts)],
        );

        $validatedProofs = [];
        foreach ($proofJwts as $proofJwt) {
            $validatedProofs[] = $this->validateProof($proofJwt, $accessToken);
        }

        return $validatedProofs;
    }


    /**
     * A configuration which advertises no proof type has nothing to validate a proof against.
     *
     * Silently ignoring one would be worse than refusing it: the wallet built a proof, sent it, and got
     * back a credential bound to something else, with nothing on it to say its key went unused.
     *
     * @param array<array-key,mixed> $requestData
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function refuseSuppliedProofs(array $requestData): void
    {
        if (
            array_key_exists(ClaimsEnum::Proof->value, $requestData) ||
            array_key_exists(ClaimsEnum::Proofs->value, $requestData)
        ) {
            throw new CredentialRequestException(
                'invalid_credential_request',
                'This credential configuration issues credentials which are not bound to a holder key, ' .
                'and advertises no proof type, so a key proof can not be accepted.',
            );
        }
    }


    /**
     * @param array<array-key,mixed> $requestData
     * @return list<non-empty-string>
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function extractProofJwts(array $requestData): array
    {
        // The singular parameter is the pre-final shape of this request. Accepting it would mean
        // accepting a request the metadata this configuration publishes does not describe.
        if (array_key_exists(ClaimsEnum::Proof->value, $requestData)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The "proof" parameter is not supported. Send the key proof in the "proofs" parameter.',
            );
        }

        /** @psalm-suppress MixedAssignment */
        $proofs = $requestData[ClaimsEnum::Proofs->value] ?? null;

        if (!is_array($proofs) || $proofs === []) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The "proofs" parameter is required for this credential configuration.',
            );
        }

        if (count($proofs) !== 1) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The "proofs" parameter must name exactly one proof type.',
            );
        }

        if ((string)array_key_first($proofs) !== self::PROOF_TYPE_JWT) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf('The only supported proof type is "%s".', self::PROOF_TYPE_JWT),
            );
        }

        /** @psalm-suppress MixedAssignment */
        $proofValues = reset($proofs);

        if (!is_array($proofValues) || !array_is_list($proofValues) || $proofValues === []) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The "proofs" parameter must carry a non-empty array of key proofs.',
            );
        }

        // Each proof issues a credential and claims a Status List entry of its own, so an uncapped array
        // lets one request spend an arbitrary amount of storage and signing work. The same number is
        // published as `batch_credential_issuance.batch_size`, so a wallet can see it beforehand.
        if (count($proofValues) > ModuleConfig::VCI_BATCH_SIZE) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'The "proofs" parameter carries more key proofs than the advertised batch size of %d.',
                    ModuleConfig::VCI_BATCH_SIZE,
                ),
            );
        }

        $proofJwts = [];

        /** @var mixed $proofValue */
        foreach ($proofValues as $proofValue) {
            if (!is_string($proofValue) || $proofValue === '') {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'Every entry in the "proofs" parameter must be a key proof in compact serialization.',
                );
            }

            $proofJwts[] = $proofValue;
        }

        return $proofJwts;
    }


    /**
     * @param non-empty-string $proofJwt
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function validateProof(string $proofJwt, AccessTokenEntity $accessToken): ValidatedOpenId4VciProof
    {
        try {
            $proof = $this->verifiableCredentials->openId4VciProofFactory()->fromToken($proofJwt);
        } catch (Throwable $throwable) {
            $this->loggerService->warning('Key proof could not be parsed.', ['error' => $throwable->getMessage()]);

            throw new CredentialRequestException('invalid_proof', 'Key proof could not be parsed.');
        }

        try {
            $this->validateAlgorithm($proof);
            $this->validateAudience($proof);
            $this->validateIssuer($proof, $accessToken);

            [$jwk, $subject, $keyId] = $this->resolveKeySource($proof);

            try {
                $proof->verifyWithKey($jwk);
            } catch (Throwable $throwable) {
                $this->loggerService->warning(
                    'Key proof signature could not be verified.',
                    ['error' => $throwable->getMessage()],
                );

                throw new CredentialRequestException('invalid_proof', 'Key proof signature could not be verified.');
            }

            // After the signature, so a nonce is only ever reported on a proof which is otherwise sound.
            $this->validateNonce($proof);

            $this->loggerService->debug('Key proof validated.', ['subject' => $subject]);

            return new ValidatedOpenId4VciProof($proof, $subject, $keyId);
        } catch (CredentialRequestException $credentialRequestException) {
            throw $credentialRequestException;
        } catch (Throwable $throwable) {
            // Whatever else went wrong here went wrong about a proof, and a proof this issuer can not
            // make sense of is refused rather than allowed to surface as a server error - which would
            // be the one path back to issuing without a proof having been checked.
            $this->loggerService->warning(
                'Key proof could not be validated.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException('invalid_proof', 'Key proof could not be validated.');
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateAlgorithm(OpenId4VciProof $proof): void
    {
        $advertisedAlgorithms = $this->moduleConfig->getSupportedAlgorithms()
            ->getSignatureAlgorithmBag()
            ->getAllNamesUnique();

        // Advertised, not merely usable with the key. A wallet was told which algorithms this issuer
        // accepts for key proofs, and honouring one it was not told about verifies a signature under
        // rules nobody published.
        if (!in_array($proof->getAlgorithm(), $advertisedAlgorithms, true)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof is signed with an algorithm this issuer does not advertise for key proofs.',
            );
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateAudience(OpenId4VciProof $proof): void
    {
        /** @psalm-suppress MixedAssignment */
        $audience = $proof->getPayloadClaim(ClaimsEnum::Aud->value);

        // The claim as it arrived, rather than through getAudience(), which normalises a string and an
        // array into the same shape. What has to hold is that this issuer is the only audience named:
        // an array naming this issuer alongside somebody else is a proof built for that other place
        // which this issuer merely happens to be listed in, and normalising first leaves nothing to
        // tell the two apart but a count. Both spellings of a single audience are accepted, since
        // RFC 7519 allows either and they say the same thing.
        if (is_array($audience) && array_is_list($audience) && count($audience) === 1) {
            /** @psalm-suppress MixedAssignment */
            $audience = reset($audience);
        }

        if (!is_string($audience) || $audience !== $this->moduleConfig->getIssuer()) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof is not addressed to this Credential Issuer, or names another audience ' .
                'alongside it.',
            );
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateIssuer(OpenId4VciProof $proof, AccessTokenEntity $accessToken): void
    {
        $proofIssuer = $proof->getIssuer();

        // A pre-authorized code redeemed without a `client_id` identifies no wallet at all, so there is
        // nothing an `iss` claim could be checked against, and OpenID4VCI has the wallet omit it.
        // Recognised from the flow plus the absence of a bound client id rather than from the stored
        // client entity, which names the client the offer was created for either way.
        if (
            $accessToken->getFlowTypeEnum() === FlowTypeEnum::VciPreAuthorizedCode &&
            $accessToken->getBoundClientId() === null
        ) {
            if ($proofIssuer !== null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'Key proof must not carry an "iss" claim, because the access token it accompanies ' .
                    'identifies no client.',
                );
            }

            return;
        }

        // Absence is accepted. OpenID4VCI constrains this claim when it is present; requiring it here
        // would refuse a proof the specification permits, and it is the DIIP profile, applied per
        // credential configuration, where presence becomes a requirement.
        if ($proofIssuer === null) {
            return;
        }

        // The identifier a non-registered wallet is actually known by travels separately from the client
        // entity, which in those flows is a stand-in shared by every such wallet.
        $clientId = $accessToken->getBoundClientId() ?? $accessToken->getClient()->getIdentifier();

        if ($proofIssuer !== $clientId) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof "iss" claim does not name the client the access token was issued to.',
            );
        }
    }


    /**
     * Work out which key the proof is verified against, and what its credential is bound to.
     *
     * @return array{0: mixed[], 1: string, 2: ?string} The key, the holder identifier, and the
     * verification method the proof named.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     */
    protected function resolveKeySource(OpenId4VciProof $proof): array
    {
        $keyId = $proof->getKeyId();
        $headerJwk = $proof->getJsonWebKey();
        $certificateChain = $proof->getX509CertificateChain();

        $keySources = array_filter(
            [$keyId, $headerJwk, $certificateChain],
            static fn(mixed $keySource): bool => $keySource !== null,
        );

        if (count($keySources) !== 1) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The key proof header must carry exactly one of "kid", "jwk" or "x5c".',
            );
        }

        if ($certificateChain !== null) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proofs carrying an "x5c" header are not supported by this issuer.',
            );
        }

        if ($headerJwk !== null) {
            $this->assertPublicJwk($headerJwk);

            try {
                $subject = $this->did->didJwkResolver()->generateDidJwkFromJwk($headerJwk);
            } catch (JsonException) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'The "jwk" header of the key proof could not be read as a key.',
                );
            }

            // No verification method was named, so there is none to carry into the credential's `cnf`.
            return [$headerJwk, $subject, null];
        }

        /** @var non-empty-string $keyId */
        $did = explode('#', $keyId, 2)[0];

        try {
            if (str_starts_with($keyId, 'did:key:z')) {
                return [$this->did->didKeyResolver()->extractJwkFromDidKey($did), $did, $keyId];
            }

            if (str_starts_with($keyId, 'did:jwk:')) {
                return [$this->did->didJwkResolver()->extractJwkFromDidJwk($did), $did, $keyId];
            }
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key proof names a verification method which could not be resolved.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof "kid" header names a verification method which could not be resolved.',
            );
        }

        $this->loggerService->warning('Key proof names a verification method of an unsupported type.');

        throw new CredentialRequestException(
            'invalid_proof',
            'Key proof "kid" header names a verification method this issuer can not resolve.',
        );
    }


    /**
     * @param mixed[] $jwk
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function assertPublicJwk(array $jwk): void
    {
        /** @psalm-suppress MixedAssignment */
        $keyType = $jwk['kty'] ?? null;

        if (!is_string($keyType) || !array_key_exists($keyType, self::PUBLIC_JWK_MEMBERS_BY_KEY_TYPE)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The "jwk" header of the key proof is of a key type this issuer does not accept.',
            );
        }

        $allowedMembers = array_merge(
            self::COMMON_JWK_MEMBERS,
            self::PUBLIC_JWK_MEMBERS_BY_KEY_TYPE[$keyType],
        );

        $unexpectedMembers = array_diff(array_keys($jwk), $allowedMembers);

        if ($unexpectedMembers !== []) {
            // The member names go to the log rather than into the response. As far as this issuer knows
            // they are attacker-chosen text, and echoing them back says nothing that naming the key type
            // does not.
            $this->loggerService->warning(
                'The "jwk" header of a key proof carried members which are not public key material.',
                ['keyType' => $keyType, 'members' => array_values($unexpectedMembers)],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'The "jwk" header of the key proof carries members which are not part of a public ' .
                    '"%s" key. Private key material must never be sent.',
                    $keyType,
                ),
            );
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateNonce(OpenId4VciProof $proof): void
    {
        $nonce = $proof->getNonce();

        // This issuer publishes a Nonce Endpoint, which is what makes the nonce mandatory rather than
        // optional. Without it a proof stays replayable for as long as it remains unexpired.
        if (!is_string($nonce)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof must carry a "nonce" claim obtained from the Nonce Endpoint.',
            );
        }

        if (!$this->nonceService->validateNonce($nonce)) {
            // Deliberately its own error code, so a wallet knows to ask for a fresh nonce and retry
            // rather than to go looking for a fault in the proof it built.
            throw new CredentialRequestException('invalid_nonce', 'c_nonce is invalid or expired.');
        }
    }
}
