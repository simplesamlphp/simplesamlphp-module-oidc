<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use Jose\Component\Core\JWK;
use JsonException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\DidResolutionBudget;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCredentialProofTypes;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\VerificationRelationshipEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidDocument;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\Did\ResolvedVerificationMethod;
use SimpleSAML\OpenID\Exceptions\X509TrustStoreException;
use SimpleSAML\OpenID\Helpers\Jwk as JwkHelper;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\KeyAttestation;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use stdClass;
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
 * receives. It is also request-wide in what it will spend: the DIDs a request names are resolved under
 * one shared budget rather than each proof getting the whole of one to itself.
 *
 * Two rulesets, not one. The OpenID4VCI rules apply to every key proof this issuer accepts. The DIIP
 * profile's identifier rules apply on top of them, for credential configurations which are set to
 * `DiipProofBound` - per configuration, because DIIP's requirements are additive and a deployment may
 * offer conformant configurations alongside ones which accept inline keys or `did:key` holders.
 *
 * Two proof types, each where the credential configuration offers it (ModuleConfig::getVciCredentialProofTypesFor()):
 * `jwt` (Appendix F.1), one credential per proof, which carries a key attestation of its key where the
 * configuration requires one; and `attestation` (Appendix F.3), a key attestation without a proof of possession, one
 * credential per attested key. A key attestation is verified by KeyAttestationVerifier.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\OpenId4VciProofValidatorTest
 */
class OpenId4VciProofValidator
{
    /**
     * How many distinct DIDs one Credential Request may send this deployment out to fetch.
     *
     * Lower than the batch size on purpose. A batch of eight credentials for one wallet names one
     * holder DID eight times over, or eight `did:jwk` identifiers which are resolved without leaving
     * this process; eight distinct `did:web` hosts in one request is not a wallet collecting
     * credentials, it is a request using this issuer to reach eight places.
     */
    final public const int MAX_NETWORK_RESOLVED_DIDS = 4;

    /**
     * How long everything one Credential Request has to fetch may take, in total.
     *
     * The per-fetch timeout bounds a single fetch and says nothing about a request making several, so
     * this is the bound that actually holds the request open time down. It is passed into each
     * resolution rather than applied afterwards, so a fetch which would overrun it is not started.
     */
    final public const int REQUEST_DEADLINE_SECONDS = 15;

    /**
     * The JOSE header parameter of a key proof carrying a key attestation (OpenID4VCI 1.0 Appendices D and F.1).
     */
    final public const string HEADER_KEY_ATTESTATION = 'key_attestation';

    /**
     * The key proof members which, when present, have to hold a value: the header parameters first, then the
     * claims.
     *
     * The getters read a member written as null the same way as one left out, so `kid: null` next to a `jwk`
     * passed as a header naming one key, and `iss: null` as a proof which omits the claim. None of these is
     * defined to take null: a key identifier and an `iss` are strings, a key is a JSON object, a certificate
     * chain and a trust chain are arrays, and a key attestation is a JWT. Checked by name, so that a member
     * sent as null is never read as one not sent.
     */
    protected const array NON_NULL_HEADER_PARAMETERS = [
        ClaimsEnum::Kid->value,
        ClaimsEnum::Jwk->value,
        ClaimsEnum::X5c->value,
        self::HEADER_KEY_ATTESTATION,
        ClaimsEnum::TrustChain->value,
    ];

    /** {@see NON_NULL_HEADER_PARAMETERS} */
    protected const array NON_NULL_PAYLOAD_CLAIMS = [
        ClaimsEnum::Iss->value,
    ];

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


    /** The DID facade for this request, obtained on first use. {@see did()} */
    protected ?Did $did = null;


    /**
     * @param \SimpleSAML\Module\oidc\Factories\DidFactory $didFactory The factory rather than the facade
     *        it builds. This validator is a constructor argument of the Credential Endpoint controller,
     *        and the container resolves every such argument before that controller's constructor body
     *        runs - so taking a built facade here made a deployment with Verifiable Credentials switched
     *        off answer that endpoint by failing on DID settings it has no use for, instead of by the
     *        403 the guard is there to give. Nothing about a proof is validated at construction, so
     *        nothing about DID needs building then either.
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly DidFactory $didFactory,
        protected readonly NonceService $nonceService,
        protected readonly LoggerService $loggerService,
        protected readonly KeyAttestationVerifier $keyAttestationVerifier,
    ) {
    }


    /**
     * The DID facade, built the first time a proof actually needs one.
     *
     * The factory keeps the built facade, so this is the same instance every other collaborator in the
     * request gets rather than one more of its own.
     *
     * Building it reads this issuer's configuration and nothing of the proof (DidFactory::build()), so whatever
     * stops it is refused as the configuration's fault, a ConfigurationError, which the Credential Endpoint answers
     * with a server error. Let through as thrown, it would reach the catch-all of validateProof() and be answered
     * as an invalid proof, the wallet's fault: a cache adapter which can not be built, an outbound destination the
     * library refuses, a cache duration which is not an interval, an option which is not an array.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    protected function did(): Did
    {
        if ($this->did instanceof Did) {
            return $this->did;
        }

        try {
            return $this->did = $this->didFactory->build();
        } catch (ConfigurationError $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                'DID resolution could not be set up: ' . $throwable->getMessage(),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }
    }


    /**
     * Validate everything a Credential Request says about holder binding.
     *
     * @param array<array-key,mixed> $requestData
     * @param ?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCredentialProofTypes $proofTypes The proof
     * types the credential configuration takes, or null for `jwt` proofs without key attestations.
     * @return list<?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof> One
     * entry per credential the request is to be issued, in the order the proofs arrived, or the order an
     * attestation proof lists its keys in. A null entry means an unbound credential, which only a proofless
     * configuration produces.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException When the request is refused.
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Error\ConfigurationError Also when the trust anchors of key attestations can not be used.
     * @throws \SimpleSAML\OpenID\Exceptions\X509TrustStoreException When a key attestation's certificate path can
     * not be validated for want of its temporary files.
     * @throws \JsonException
     */
    public function validateRequest(
        array $requestData,
        VciCredentialBindingPolicyEnum $bindingPolicy,
        AccessTokenEntity $accessToken,
        ?VciCredentialProofTypes $proofTypes = null,
    ): array {
        if (!$bindingPolicy->requiresKeyProof()) {
            $this->refuseSuppliedProofs($requestData);

            return [null];
        }

        $proofTypes ??= VciCredentialProofTypes::jwtOnly();

        [$proofType, $proofJwts] = $this->extractProofJwts($requestData, $proofTypes);

        $this->loggerService->debug(
            'Validating key proofs before issuing anything.',
            [
                'count' => count($proofJwts),
                'proofType' => $proofType->value,
                'bindingPolicy' => $bindingPolicy->value,
            ],
        );

        // Shared by every proof in the request, so that what one request may spend on resolving DIDs is
        // bounded once rather than per proof - a per-proof deadline multiplies by the batch size.
        $didResolutionBudget = new DidResolutionBudget(
            microtime(true) + (float)self::REQUEST_DEADLINE_SECONDS,
            self::MAX_NETWORK_RESOLVED_DIDS,
        );

        // Asked once, outside the validation of a proof, which takes whatever goes wrong in it for the proof's
        // fault.
        $isVciHaipEnabled = $this->moduleConfig->getVciHaipEnabled();

        // So are the trust anchors of key attestations: when they can not be used, the fault is this issuer's.
        if ($proofTypes->requiresKeyAttestation($proofType)) {
            $this->keyAttestationVerifier->getTrustAnchors();
        }

        $validatedProofs = [];
        $provenKeyThumbprints = [];
        foreach ($proofJwts as $proofJwt) {
            $validatedProofsOfJwt = $proofType === VciProofTypeEnum::Attestation ?
            $this->validateAttestationProof(
                $proofJwt,
                $bindingPolicy,
                $proofTypes->getKeyAttestationRequirementsFor($proofType),
                $isVciHaipEnabled,
            ) :
            [
                $this->validateProof(
                    $proofJwt,
                    $accessToken,
                    $bindingPolicy,
                    $didResolutionBudget,
                    $isVciHaipEnabled,
                    $proofTypes,
                ),
            ];

            foreach ($validatedProofsOfJwt as $validatedProof) {
                // OpenID4VCI 1.0 section 8.3: "Each key provided by the Wallet is used to bind to, at most, one
                // Credential". Compared by thumbprint, so the same key named twice in two ways (inline and by a
                // verification method, or under two DID URLs) is still one key. Refused rather than issued one
                // credential for: a wallet repeating a key has made a mistake which a shorter batch would hide,
                // and credentials bound to one key are linkable by it. The keys of an attestation proof as well.
                if (isset($provenKeyThumbprints[$validatedProof->getKeyThumbprint()])) {
                    throw new CredentialRequestException(
                        'invalid_proof',
                        $proofType === VciProofTypeEnum::Attestation ?
                        'Each key the key attestation attests must be a different key, and two of them are the same ' .
                        'one.' :
                        'Each key proof must prove a different key, and two of them prove the same one.',
                    );
                }

                $provenKeyThumbprints[$validatedProof->getKeyThumbprint()] = true;
                $validatedProofs[] = $validatedProof;
            }
        }

        return $validatedProofs;
    }


    /**
     * A configuration which advertises no proof type has nothing to validate a proof against.
     *
     * Silently ignoring one would be worse than refusing it: the wallet built a proof, sent it, and got
     * back a credential bound to something else, with nothing on it to say its key went unused.
     *
     * That is about `proofs`, the parameter OpenID4VCI 1.0 defines. The pre-final singular `proof` is not
     * one of its parameters, and section 8.2 has an issuer ignore the parameters it does not recognize, so
     * a request carrying it is issued as one without it: the metadata this configuration publishes, with
     * no binding methods and no proof types, already told the wallet that what it issues is bound to no key.
     *
     * @param array<array-key,mixed> $requestData
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function refuseSuppliedProofs(array $requestData): void
    {
        if (array_key_exists(ClaimsEnum::Proofs->value, $requestData)) {
            throw new CredentialRequestException(
                'invalid_credential_request',
                'This credential configuration issues credentials which are not bound to a holder key, ' .
                'and advertises no proof type, so a key proof can not be accepted.',
            );
        }
    }


    /**
     * @param array<array-key,mixed> $requestData
     * @return array{0: \SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum, 1: non-empty-list<non-empty-string>}
     * The proof type the request uses, and its proofs.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function extractProofJwts(array $requestData, VciCredentialProofTypes $proofTypes): array
    {
        // Only `proofs` is read. The pre-final singular `proof` is not an OpenID4VCI 1.0 parameter, and
        // section 8.2 has an issuer ignore the parameters it does not recognize: a request carrying both is
        // served by its `proofs`, and one carrying `proof` alone is refused below for lacking `proofs`.
        /** @psalm-suppress MixedAssignment */
        $proofs = $requestData[ClaimsEnum::Proofs->value] ?? null;

        if (!is_array($proofs) || $proofs === []) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The proofs parameter is required for this credential configuration.',
            );
        }

        if (count($proofs) !== 1) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The proofs parameter must name exactly one proof type.',
            );
        }

        $proofType = VciProofTypeEnum::tryFrom((string)array_key_first($proofs));

        // The configuration's own proof types, which its metadata advertises; not every type this issuer verifies.
        if ($proofType === null || !$proofTypes->offers($proofType)) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'This credential configuration takes key proofs of the type %s only.',
                    implode(
                        ' or ',
                        array_map(
                            static fn(VciProofTypeEnum $offered): string => $offered->value,
                            $proofTypes->getOffered(),
                        ),
                    ),
                ),
            );
        }

        /** @psalm-suppress MixedAssignment */
        $proofValues = reset($proofs);

        if (!is_array($proofValues) || !array_is_list($proofValues) || $proofValues === []) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The proofs parameter must carry a non-empty array of key proofs.',
            );
        }

        // Appendix F: an attestation proof is "an array that contains exactly one JWT". The keys it attests are
        // capped as proofs are (validateAttestationProof()).
        if ($proofType === VciProofTypeEnum::Attestation && count($proofValues) !== 1) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The proofs parameter must carry exactly one key attestation for the attestation proof type.',
            );
        }

        // Each proof issues a credential and claims a Status List entry of its own, so an uncapped array
        // lets one request spend an arbitrary amount of storage and signing work. The same number is
        // published as `batch_credential_issuance.batch_size`, so a wallet can see it beforehand.
        if (count($proofValues) > ModuleConfig::VCI_BATCH_SIZE) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'The proofs parameter carries more key proofs than the advertised batch size of %d.',
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
                    'Every entry in the proofs parameter must be a key proof in compact serialization.',
                );
            }

            $proofJwts[] = $proofValue;
        }

        return [$proofType, $proofJwts];
    }


    /**
     * @param non-empty-string $proofJwt
     * @param ?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCredentialProofTypes $proofTypes Whether the
     * proof has to carry a key attestation, and what is required of it; null for `jwt` proofs without one.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\X509TrustStoreException
     */
    protected function validateProof(
        string $proofJwt,
        AccessTokenEntity $accessToken,
        VciCredentialBindingPolicyEnum $bindingPolicy,
        DidResolutionBudget $didResolutionBudget,
        bool $isVciHaipEnabled = false,
        ?VciCredentialProofTypes $proofTypes = null,
    ): ValidatedOpenId4VciProof {
        try {
            $proof = $this->verifiableCredentials->openId4VciProofFactory()->fromToken($proofJwt);
        } catch (Throwable $throwable) {
            $this->loggerService->warning('Key proof could not be parsed.', ['error' => $throwable->getMessage()]);

            throw new CredentialRequestException('invalid_proof', 'Key proof could not be parsed.');
        }

        try {
            $this->validateAlgorithm($proof);
            $this->refuseNullMembers($proof);
            $this->validateAttachedJwsAlgorithms($proof, $proofJwt);
            $this->validateAudience($proof);
            $this->validateIssuer($proof, $accessToken);

            [$jwk, $subject, $keyId, $holderJwk] = $this->resolveKeySource(
                $proof,
                $bindingPolicy,
                $didResolutionBudget,
            );

            $jwk = $this->enforceCanonicalPublicKey($jwk);

            // While issuance follows HAIP, the key is one FAPI 2.0 lets sign with (section 5.4.1): an RSA key of 2048
            // bits at least. Asked before the signature, which a key that does not fit is not trusted to verify.
            if ($isVciHaipEnabled) {
                $this->enforceKeyFitsTheAlgorithm($proof, $jwk);
            }

            try {
                $proof->verifyWithKey($jwk);
            } catch (Throwable $throwable) {
                $this->loggerService->warning(
                    'Key proof signature could not be verified.',
                    ['error' => $throwable->getMessage()],
                );

                throw new CredentialRequestException('invalid_proof', 'Key proof signature could not be verified.');
            }

            // Appendix F.1, where the configuration requires a key attestation of a jwt proof: one which holds, of
            // the key the proof was just verified with.
            $keyAttestation = $proofTypes !== null && $proofTypes->requiresKeyAttestation(VciProofTypeEnum::Jwt) ?
            $this->verifyKeyAttestationOfProof(
                $proof,
                $jwk,
                $proofTypes->getKeyAttestationRequirementsFor(VciProofTypeEnum::Jwt),
            ) :
            null;

            // After the signature, so a nonce is only ever reported on a proof which is otherwise sound.
            $this->validateNonce($proof);

            if ($keyAttestation instanceof KeyAttestation) {
                $this->validateKeyAttestationNonce($keyAttestation);
            }

            // RFC 7638: computed over the members which define the key, so it is the same however the key
            // was written down or found.
            $keyThumbprint = (new JWK($jwk))->thumbprint('sha256');

            // While issuance follows HAIP, the credential names the key itself (`cnf.jwk`, HAIP 1.0 section 6.1), the
            // key a verification method names too: by the members RFC 7638 has define the key, not the DID
            // document's members about it. A key sent inline is named by the `jwk` header as it was sent.
            $confirmationJwk = $isVciHaipEnabled && $keyId !== null ?
            $this->verifiableCredentials->helpers()->jwk()->getRequiredMembers($jwk) :
            null;

            $validatedProof = new ValidatedOpenId4VciProof(
                $proof,
                $subject,
                $keyId,
                $holderJwk,
                $keyThumbprint,
                $confirmationJwk,
            );

            $this->loggerService->debug(
                'Key proof validated.',
                ['holderDidMethod' => $validatedProof->getSubjectDidMethod()],
            );

            return $validatedProof;
        } catch (CredentialRequestException | ConfigurationError | X509TrustStoreException $exception) {
            // A configuration which can not be used, or a trust store which can not be set up, is this issuer's fault,
            // not the proof's: the Credential Endpoint answers it with a server error, and issues nothing.
            throw $exception;
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
     * The key attestation a jwt proof carries in its `key_attestation` header, verified (KeyAttestationVerifier), of
     * the key the proof was verified with: Appendix D.1 has "the Credential Issuer MUST validate that the JWT used as a
     * proof is signed by a key contained in the attestation in the JOSE Header".
     *
     * One credential is issued for the proof, bound to its key, not one for each key the attestation attests, which
     * Appendix F.1 has as a SHOULD: the proof proves possession of its own key only, a batch of proofs commonly carries
     * one attestation of all their keys (HAIP 1.0 section 4.5.1), and the attestation proof type is the way to ask for
     * a credential for each attested key.
     *
     * @param array<string,mixed> $jwk The key the proof was verified with.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\X509TrustStoreException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function verifyKeyAttestationOfProof(
        OpenId4VciProof $proof,
        array $jwk,
        ?VciKeyAttestationRequirements $requirements,
    ): KeyAttestation {
        /** @psalm-suppress MixedAssignment */
        $keyAttestationJwt = $proof->hasHeaderClaim(self::HEADER_KEY_ATTESTATION) ?
        $proof->getHeaderClaim(self::HEADER_KEY_ATTESTATION) :
        null;

        if ($keyAttestationJwt === null) {
            throw new CredentialRequestException(
                'invalid_proof',
                'This credential configuration requires every key proof to carry a key attestation in its ' .
                'key_attestation header.',
            );
        }

        // A JWT whose alg is advertised, which validateAttachedJwsAlgorithms() asked of a header carrying one.
        if (!is_string($keyAttestationJwt) || $keyAttestationJwt === '') {
            throw new CredentialRequestException(
                'invalid_proof',
                'The key_attestation header parameter of the key proof must be a JWT.',
            );
        }

        $keyAttestation = $this->keyAttestationVerifier->verify(
            $keyAttestationJwt,
            VciProofTypeEnum::Jwt,
            $requirements,
        );

        if (!$keyAttestation->hasAttestedKey($jwk)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The key proof is not signed with a key its key attestation attests.',
            );
        }

        return $keyAttestation;
    }


    /**
     * An attestation proof (Appendix F.3): a key attestation without a proof of possession, verified
     * (KeyAttestationVerifier), whose attested keys each get a credential bound to them, as F.3 has it ("SHOULD issue
     * a Credential for each cryptographic public key specified in the attested_keys claim").
     *
     * Each attested key is bound as a key sent inline is: the credential's subject is the `did:jwk` made from it, and
     * its `cnf` names the key itself. More keys than the batch size are refused, as more proofs are.
     *
     * @param non-empty-string $keyAttestationJwt
     * @return non-empty-list<\SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof> One
     * per attested key, in the order the attestation lists them.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\X509TrustStoreException
     */
    protected function validateAttestationProof(
        string $keyAttestationJwt,
        VciCredentialBindingPolicyEnum $bindingPolicy,
        ?VciKeyAttestationRequirements $requirements,
        bool $isVciHaipEnabled,
    ): array {
        // ModuleConfig refuses the attestation proof type for such a configuration; refused here too, since the keys
        // an attestation carries can be bound no other way.
        if (!$bindingPolicy->acceptsInlineKey()) {
            throw new CredentialRequestException(
                'invalid_proof',
                'This credential configuration does not take key attestations as proofs.',
            );
        }

        try {
            // Appendix F.3: "the value of the alg JWT header of the key attestation MUST match one of the entries in
            // the proof_signing_alg_values_supported metadata parameter".
            $this->assertSignedWithAnAdvertisedAlgorithm($keyAttestationJwt, VciProofTypeEnum::Attestation->value);

            $keyAttestation = $this->keyAttestationVerifier->verify(
                $keyAttestationJwt,
                VciProofTypeEnum::Attestation,
                $requirements,
            );

            $attestedKeys = $keyAttestation->getAttestedKeys();

            if (count($attestedKeys) > ModuleConfig::VCI_BATCH_SIZE) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    sprintf(
                        'The key attestation attests more keys than the advertised batch size of %d.',
                        ModuleConfig::VCI_BATCH_SIZE,
                    ),
                );
            }

            $validatedProofs = [];
            $attestedKeyThumbprints = [];

            // Each held to the members of a public key of an asymmetric type, in their canonical representation, as
            // the library reads them (Helpers\Jwk::enforcePublicKey()), which is what a key sent inline is held to.
            foreach ($attestedKeys as $attestedKey) {
                // While issuance follows HAIP, an RSA key of 2048 bits at least (FAPI 2.0 section 5.4.1), as of a key
                // a jwt proof is verified with. An attested key signs nothing here, so it is asked of the key alone.
                if (
                    $isVciHaipEnabled &&
                    ($attestedKey['kty'] ?? null) === 'RSA' &&
                    $this->verifiableCredentials->helpers()->jwk()->getRsaModulusBitLength($attestedKey) <
                    JwkHelper::MIN_RSA_MODULUS_BITS
                ) {
                    throw new CredentialRequestException(
                        'invalid_proof',
                        'An attested key is not one credential issuance following HAIP binds to: it takes RSA keys ' .
                        'of 2048 bits at least.',
                    );
                }

                // Section 8.3, as validateRequest() has it for proofs, asked here as well so that it comes before
                // the nonce: a wallet is not sent for a fresh nonce for an attestation which stays refused.
                $thumbprint = (new JWK($attestedKey))->thumbprint('sha256');

                if (isset($attestedKeyThumbprints[$thumbprint])) {
                    throw new CredentialRequestException(
                        'invalid_proof',
                        'Each key the key attestation attests must be a different key, and two of them are the same ' .
                        'one.',
                    );
                }

                $attestedKeyThumbprints[$thumbprint] = true;

                $validatedProofs[] = new ValidatedOpenId4VciProof(
                    $keyAttestation,
                    $this->didFactory->didJwkResolver()->generateDidJwkFromJwk($attestedKey),
                    null,
                    $attestedKey,
                    $thumbprint,
                );
            }

            // Last, so a nonce is only ever reported on an attestation which is otherwise sound.
            $this->validateKeyAttestationNonce($keyAttestation);

            $this->loggerService->debug('Attestation proof validated.', ['attestedKeys' => count($validatedProofs)]);

            return $validatedProofs;
        } catch (CredentialRequestException | ConfigurationError | X509TrustStoreException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            // As for a jwt proof (validateProof()): what this issuer can not make sense of is refused.
            $this->loggerService->warning(
                'Attestation proof could not be validated.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException('invalid_proof', 'Attestation proof could not be validated.');
        }
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateAlgorithm(OpenId4VciProof $proof): void
    {
        // Advertised, not merely usable with the key. A wallet was told which algorithms this issuer
        // accepts for key proofs, and honouring one it was not told about verifies a signature under
        // rules nobody published.
        if (!in_array($proof->getAlgorithm(), $this->advertisedProofSigningAlgorithms(), true)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proof is signed with an algorithm this issuer does not advertise for key proofs.',
            );
        }
    }


    /**
     * The algorithms this issuer advertises as `proof_signing_alg_values_supported` for the `jwt` proof type, in
     * every configuration which takes a key proof (CredentialIssuerMetadataService).
     *
     * @return string[]
     */
    protected function advertisedProofSigningAlgorithms(): array
    {
        return $this->moduleConfig->getSupportedAlgorithms()
            ->getSignatureAlgorithmBag()
            ->getAllNamesUnique();
    }


    /**
     * Refuse a key proof which writes any of the members in NON_NULL_HEADER_PARAMETERS or
     * NON_NULL_PAYLOAD_CLAIMS as null.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function refuseNullMembers(OpenId4VciProof $proof): void
    {
        foreach (self::NON_NULL_HEADER_PARAMETERS as $parameter) {
            if ($proof->hasHeaderClaim($parameter) && $proof->getHeaderClaim($parameter) === null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    sprintf('The %s header parameter of the key proof is null, which it may not be.', $parameter),
                );
            }
        }

        foreach (self::NON_NULL_PAYLOAD_CLAIMS as $claim) {
            if ($proof->hasPayloadClaim($claim) && $proof->getPayloadClaim($claim) === null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    sprintf('The %s claim of the key proof is null, which it may not be.', $claim),
                );
            }
        }
    }


    /**
     * OpenID4VCI 1.0 Appendix F.1: "the alg JWT header of the key proof, and if present, the alg JOSE headers of
     * both key_attestation and trust_chain, MUST match one of the values listed in the
     * proof_signing_alg_values_supported metadata parameter".
     *
     * That is all that is checked of them here. A key attestation is verified where the credential configuration
     * requires one of a jwt proof (verifyKeyAttestationOfProof()), and nowhere else; a trust chain is never read. So
     * a proof carrying either, where nothing requires it, is otherwise taken as a proof carrying neither: its key is
     * the one its `kid` or `jwk` header names, and that is the key its signature is verified with. The `alg` is read
     * from a protected header nothing has checked yet; what holds is that a wallet sending one was told the
     * algorithms to sign it with.
     *
     * @param non-empty-string $proofJwt The proof as it was sent, whose header says what JSON type a member is.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\JwsException
     */
    protected function validateAttachedJwsAlgorithms(OpenId4VciProof $proof, string $proofJwt): void
    {
        if ($proof->hasHeaderClaim(self::HEADER_KEY_ATTESTATION)) {
            $this->assertSignedWithAnAdvertisedAlgorithm(
                $proof->getHeaderClaim(self::HEADER_KEY_ATTESTATION),
                self::HEADER_KEY_ATTESTATION,
            );
        }

        if (!$proof->hasHeaderClaim(ClaimsEnum::TrustChain->value)) {
            return;
        }

        /** @psalm-suppress MixedAssignment */
        $trustChain = $proof->getHeaderClaim(ClaimsEnum::TrustChain->value);

        // An OpenID Federation Trust Chain: a JSON array of Entity Statements, each a JWT with an `alg` of its own.
        // The JSON type is read from the header as sent, since decoded into PHP arrays an object whose members are
        // named 0, 1 and so on reads as a list too.
        if (
            !$this->protectedHeaderHoldsJsonArray($proofJwt, ClaimsEnum::TrustChain->value) ||
            !is_array($trustChain) ||
            $trustChain === []
        ) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The trust_chain header parameter of the key proof must be a non-empty array of JWTs.',
            );
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($trustChain as $entityStatement) {
            $this->assertSignedWithAnAdvertisedAlgorithm($entityStatement, ClaimsEnum::TrustChain->value);
        }
    }


    /**
     * Whether the protected header of the compact JWS given holds a JSON array as the parameter given.
     *
     * @param non-empty-string $compactJws
     */
    protected function protectedHeaderHoldsJsonArray(string $compactJws, string $parameter): bool
    {
        try {
            /** @psalm-suppress MixedAssignment */
            $header = json_decode(
                $this->verifiableCredentials->helpers()->base64Url()->decode(explode('.', $compactJws, 2)[0]),
                false,
                512,
                JSON_THROW_ON_ERROR,
            );
        } catch (Throwable) {
            return false;
        }

        return $header instanceof stdClass && property_exists($header, $parameter) && is_array($header->$parameter);
    }


    /**
     * A JWT in compact serialization whose protected header names an algorithm this issuer advertises for key
     * proofs, or the proof carrying it is refused.
     *
     * A JWT and not merely a JWS: its payload is a claims set, a JSON object (RFC 7519 section 7.2), and its
     * header does not carry the unencoded payload option of RFC 7797 (`b64`), which the openid library refuses
     * of every JWT it parses.
     *
     * @param non-empty-string $headerParameter The header parameter of the proof which carries it, or the attestation
     * proof type for a key attestation which is the proof, for the refusal.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function assertSignedWithAnAdvertisedAlgorithm(mixed $jwt, string $headerParameter): void
    {
        $algorithm = null;

        if (is_string($jwt) && $jwt !== '') {
            try {
                $serialization = null;
                $jws = $this->verifiableCredentials->jwsSerializerManagerDecorator()
                    ->unserialize($jwt, $serialization)
                    ->jws();
                $signature = $jws->getSignature(0);
                $payload = $jws->getPayload();

                // A JWT is a JWS in compact serialization, and the one serialization which carries no
                // unprotected header for an `alg` to hide in.
                if (
                    $serialization === JwsSerializerEnum::Compact->value &&
                    !$signature->hasProtectedHeaderParameter(ClaimsEnum::B64->value) &&
                    is_string($payload) &&
                    json_decode($payload, false, 512, JSON_THROW_ON_ERROR) instanceof stdClass
                ) {
                    /** @psalm-suppress MixedAssignment */
                    $algorithm = $signature->getProtectedHeaderParameter(ClaimsEnum::Alg->value);
                }
            } catch (Throwable $throwable) {
                $this->loggerService->warning(
                    'A JWT a key proof carries could not be read.',
                    ['headerParameter' => $headerParameter, 'error' => $throwable->getMessage()],
                );
            }
        }

        if (!in_array($algorithm, $this->advertisedProofSigningAlgorithms(), true)) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    '%s signed with an algorithm this issuer advertises for key proofs.',
                    match ($headerParameter) {
                        ClaimsEnum::TrustChain->value =>
                        'The trust_chain header parameter of the key proof must hold JWTs',
                        VciProofTypeEnum::Attestation->value => 'An attestation proof must be a JWT',
                        default => sprintf('The %s header parameter of the key proof must be a JWT', $headerParameter),
                    },
                ),
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
        $client = $accessToken->getClient();

        // A pre-authorized code redeemed anonymously - no client credentials and no `client_id` - identifies
        // no wallet at all, so there is nothing an `iss` claim could be checked against, and OpenID4VCI has
        // the wallet omit it. Its token is the one issued to the generic VCI client, the stand-in for every
        // wallet which is not a registered one, with no identifier bound to it: a non-registered wallet's
        // token names the wallet through the binding, and a registered wallet's token is issued to the
        // wallet itself.
        if (
            $accessToken->getFlowTypeEnum() === FlowTypeEnum::VciPreAuthorizedCode &&
            $accessToken->getBoundClientId() === null &&
            $client instanceof ClientEntityInterface &&
            $client->isGeneric()
        ) {
            if ($proofIssuer !== null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'Key proof must not carry an iss claim, because the access token it accompanies ' .
                    'identifies no client.',
                );
            }

            return;
        }

        // Absence is accepted. OpenID4VCI constrains this claim when it is present, and requiring it
        // here would refuse a proof the specification permits. The DIIP profile does not require it
        // either: its holder binding is carried by the `kid` header, not by this claim.
        if ($proofIssuer === null) {
            return;
        }

        // The identifier a non-registered wallet is actually known by travels separately from the client
        // entity, which in those flows is a stand-in shared by every such wallet.
        $clientId = $accessToken->getBoundClientId() ?? $client->getIdentifier();

        if ($proofIssuer !== $clientId) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The iss claim of the key proof does not name the client the access token was issued to.',
            );
        }
    }


    /**
     * Work out which key the proof is verified against, and what its credential is bound to.
     *
     * @return array{0: mixed[], 1: string, 2: ?string, 3: ?mixed[]} The key, the holder identifier, the
     * verification method the proof named, and the key it carried inline. Exactly one of the last two
     * is ever set, and which one decides how the credential's `cnf` claim names the holder's key.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     */
    protected function resolveKeySource(
        OpenId4VciProof $proof,
        VciCredentialBindingPolicyEnum $bindingPolicy,
        DidResolutionBudget $didResolutionBudget,
    ): array {
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
                'The key proof header must carry exactly one of the kid, jwk and x5c parameters.',
            );
        }

        if ($certificateChain !== null) {
            throw new CredentialRequestException(
                'invalid_proof',
                'Key proofs carrying an x5c header are not supported by this issuer.',
            );
        }

        if ($headerJwk !== null) {
            // The profile's requirements are written in DID URLs, and a key sent inline names no
            // verification method for one to point at. Refused rather than resolved into a did:jwk of
            // this issuer's own making, which would be this issuer deciding how the holder is
            // identified in a credential whose whole claim is that the holder decided.
            if (!$bindingPolicy->acceptsInlineKey()) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'This credential configuration requires the key proof to name a verification ' .
                    'method in a kid header, so a key carried inline in a jwk header can not be ' .
                    'accepted.',
                );
            }

            $this->assertPublicJwk($headerJwk);

            try {
                // A local operation on a key in hand, which needs none of the DID resolution settings.
                $subject = $this->didFactory->didJwkResolver()->generateDidJwkFromJwk($headerJwk);
            } catch (JsonException) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'The jwk header of the key proof could not be read as a key.',
                );
            }

            // No verification method was named, so the credential's `cnf` names the key itself.
            return [$headerJwk, $subject, null, $headerJwk];
        }

        /** @var non-empty-string $keyId */
        $didUrl = $this->parseKeyId($keyId);

        // Before resolution, not after: a method the policy does not accept is refused without this
        // deployment first having gone out to fetch the DID naming it.
        $this->assertHolderDidMethodIsAccepted($didUrl, $bindingPolicy);

        $resolved = $this->resolveVerificationMethod($didUrl, $didResolutionBudget);

        return [$resolved->getPublicJwk(), $resolved->getDid(), $resolved->getId()->getValue(), null];
    }


    /**
     * Read the DID URL a `kid` header carries.
     *
     * @param non-empty-string $keyId
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function parseKeyId(string $keyId): DidUrl
    {
        try {
            $didUrl = new DidUrl($keyId);
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key proof "kid" header could not be read as a DID URL.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The kid header of the key proof must be a DID URL naming a verification method.',
            );
        }

        // A JOSE `kid` names a key. Resolving a bare DID and then picking a verification method out of
        // its document would be this issuer choosing which of the holder's keys the credential is bound
        // to, and writing that choice into a `cnf` claim the wallet never asserted.
        if (!$didUrl->hasFragment()) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The kid header of the key proof must name a verification method within a DID document, ' .
                'not just the DID itself.',
            );
        }

        return $didUrl;
    }


    /**
     * Resolve the verification method a `kid` header names, within what this request may spend on it.
     *
     * One call handles every DID method this library knows, including the ones which have to be fetched.
     * It replaces a chain of `str_starts_with` branches whose fall-through was the bug this class was
     * written to close: a method nobody had added a branch for left the key unresolved, and the
     * credential was issued anyway.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function resolveVerificationMethod(
        DidUrl $didUrl,
        DidResolutionBudget $didResolutionBudget,
    ): ResolvedVerificationMethod {
        $didDocument = $didResolutionBudget->recallDocument($didUrl);

        if (!$didDocument instanceof DidDocument) {
            $didDocument = $this->resolveDocument($didUrl, $didResolutionBudget);
            $didResolutionBudget->rememberDocument($didUrl, $didDocument);
        }

        try {
            return $didDocument->resolveVerificationMethod(
                $didUrl,
                // The holder authenticates with this key. The other half of the DIIP requirement, the
                // `assertionMethod` relationship, is about the keys this issuer signs with and is
                // applied where those are published.
                //
                // Applied to every proof-bound configuration rather than only the DIIP ones, which a
                // review asked to relax on the grounds that the relationship is an additive DIIP rule.
                // Declined, for three reasons. A verification relationship is how a DID controller says
                // what a key is authorized for, so honouring one listed under nothing - or under
                // `keyAgreement` - would accept a key its own controller never authorized to
                // authenticate with, which is the whole point of the relationship existing. Passing no
                // relationship is not the looser option either: it searches the document's own
                // `verificationMethod` entries only, so it would newly reject a key embedded inline
                // under `authentication`, which DID Core permits and real documents use. And the
                // holders it does turn away are the ones it should: only a `did:web` holder can be,
                // since the locally built `did:jwk` and `did:key` documents list a signature key
                // under `authentication` already, and the `did:web` one refused is the one whose own
                // document declines to say that key authenticates. Refusing it under every
                // proof-bound policy rather than only the DIIP one is the point, not a side effect.
                VerificationRelationshipEnum::Authentication,
            );
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key proof names a verification method its DID document does not offer for ' .
                'authentication.',
                ['did' => $didUrl->getDid(), 'error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The kid header of the key proof names a verification method which could not be resolved.',
            );
        }
    }


    /**
     * Fetch the document a DID describes, if this request can still afford to.
     *
     * The document rather than the single method the `kid` names, so that a batch naming several keys
     * of one holder costs one fetch. Resolving per method would have made the cap count DIDs while the
     * requests went out per proof, which is the bound the wrong way round.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function resolveDocument(
        DidUrl $didUrl,
        DidResolutionBudget $didResolutionBudget,
    ): DidDocument {
        if (!$didResolutionBudget->canResolve($didUrl)) {
            $this->loggerService->warning(
                'Credential request named more DIDs needing resolution than one request may.',
                ['did' => $didUrl->getDid(), 'max' => self::MAX_NETWORK_RESOLVED_DIDS],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'A Credential Request may name at most %d distinct DIDs which have to be resolved ' .
                    'from their host.',
                    self::MAX_NETWORK_RESOLVED_DIDS,
                ),
            );
        }

        $didResolutionBudget->noteResolutionAttempt($didUrl);

        // Outside the try, whose refusal is the wallet's: a facade which can not be built is the configuration's
        // fault (did()), whichever call reaches for it first.
        $did = $this->did();

        try {
            return $did->resolveDocument(
                $didUrl->getDid(),
                $didResolutionBudget->getDeadlineTimestamp(),
            );
        } catch (Throwable $throwable) {
            // Every way this can fail becomes the same refusal. A destination refused by policy, a name
            // which does not resolve, a timeout and an oversized body are told apart in the log and
            // nowhere else: answering them differently would make this endpoint a way to ask which
            // destinations exist inside this deployment.
            $this->loggerService->warning(
                'Key proof names a DID which could not be resolved.',
                ['did' => $didUrl->getDid(), 'error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The kid header of the key proof names a verification method which could not be resolved.',
            );
        }
    }


    /**
     * Refuse a holder whose DID method this credential configuration's binding policy does not accept.
     *
     * Which methods those are is the policy's answer rather than this class's, because the Credential
     * Issuer metadata publishes the very same answer - see
     * {@see \SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum::acceptsDidMethod()}. Two
     * lists kept in step by hand is how an issuer ends up accepting a holder identifier it never
     * advertised, or advertising one it refuses. Only the DIIP policy narrows anything today: every
     * other proof-bound configuration accepts whatever the resolver registry can resolve.
     *
     * The DIIP rule rests entirely on the `kid` header: an absolute DID URL of one of the two methods
     * the profile names, resolved under `authentication`. Nothing here reads the `iss` claim, which
     * OpenID4VCI has name the client the access token was issued to and has omitted altogether when no
     * client is identified.
     *
     * The profile's own text puts the holder's DID in `iss`, and that cannot be met at the same time as
     * OpenID4VCI's rule for an anonymous pre-authorized code, which requires the claim to be absent.
     * FIDEScommunity/DIIP#83 proposes resolving it exactly this way - drop the requirement on `iss`,
     * require an absolute DID URL in `kid` - and that proposal, still open at the time of writing, is
     * what this implements. It also reads the profile's "MUST support ... as the `iss` value" as the
     * capability requirement it is worded as: a did:jwk or did:web `iss` is accepted here, it is simply
     * not demanded, and nothing about holder binding rests on it. What proves the holder is possession
     * of a key their DID document lists, which is checked either way.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function assertHolderDidMethodIsAccepted(
        DidUrl $didUrl,
        VciCredentialBindingPolicyEnum $bindingPolicy,
    ): void {
        // The very list this configuration advertises, matched against rather than merely quoted in the
        // refusal. Asking the policy alone would accept a method it does not narrow but this deployment
        // can not resolve - refused a moment later by the resolver, but refused as an unresolvable DID
        // rather than as one this issuer never offered to accept.
        $acceptedDidMethods = $bindingPolicy->acceptableDidMethodsFrom($this->did()->supportedMethods());

        if (in_array(DidUrl::PREFIX . $didUrl->getMethod(), $acceptedDidMethods, true)) {
            return;
        }

        throw new CredentialRequestException(
            'invalid_proof',
            $acceptedDidMethods === [] ?
            // Reachable only where the profile a configuration follows names no method this deployment
            // can resolve, which leaves it nothing to name in place of the one it turned away.
            'This credential configuration can not accept the holder identifier this key proof names.' :
            sprintf(
                'This credential configuration issues to holders identified by %s only.',
                implode(' or ', $acceptedDidMethods),
            ),
        );
    }


    /**
     * The key a proof is to be verified with, sent inline or found through a verification method, in the one
     * representation RFC 7518 defines for it, or the proof is refused.
     *
     * Signature verification reads a coordinate or a modulus as a number, so a leading zero octet, or stray bits
     * after the last octet of its base64url string, verify as the same key written properly. The key's RFC 7638
     * thumbprint is computed over those strings, though, and RFC 7638 section 7 relies on the representation
     * being checked: without the check one key written two ways would be two keys to the one-key-one-credential
     * rule of validateRequest(), and bind two credentials.
     *
     * @param mixed[] $jwk
     * @return array<string,mixed>
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function enforceCanonicalPublicKey(array $jwk): array
    {
        try {
            return $this->verifiableCredentials->helpers()->jwk()->enforcePublicKey($jwk, 'key proof');
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key proof key is not a public key in its canonical representation.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The key the proof is to be verified with is not a public key in the representation RFC 7518 ' .
                'defines for it.',
            );
        }
    }


    /**
     * Enforces that the proof's key is one its algorithm can be used with, as the library has it
     * (Helpers\Jwk::enforceKeyFitsSignatureAlgorithm()): for an RSA algorithm, an RSA key of 2048 bits at least.
     *
     * @param array<string,mixed> $jwk
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function enforceKeyFitsTheAlgorithm(OpenId4VciProof $proof, array $jwk): void
    {
        try {
            $this->verifiableCredentials->helpers()->jwk()->enforceKeyFitsSignatureAlgorithm(
                $jwk,
                SignatureAlgorithmEnum::from($proof->getAlgorithm()),
                'key proof',
            );
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key proof key can not be used with the algorithm of the proof.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The key the proof is to be verified with is not one its algorithm can be used with: credential ' .
                'issuance following HAIP takes RSA keys of 2048 bits at least.',
            );
        }
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
                'The jwk header of the key proof is of a key type this issuer does not accept.',
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
                    'The jwk header of the key proof carries members which are not part of a public ' .
                    '%s key. Private key material must never be sent.',
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
                'Key proof must carry a nonce claim obtained from the Nonce Endpoint.',
            );
        }

        if (!$this->nonceService->validateNonce($nonce)) {
            // Deliberately its own error code, so a wallet knows to ask for a fresh nonce and retry
            // rather than to go looking for a fault in the proof it built.
            throw new CredentialRequestException('invalid_nonce', 'c_nonce is invalid or expired.');
        }
    }


    /**
     * A key attestation's nonce, which KeyAttestationVerifier required, has to be a c_nonce this issuer gave
     * (Appendices F.1, F.3). Not necessarily the one of the proof carrying it: each is a nonce this issuer gave, and
     * each lives as long as a nonce does.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     */
    protected function validateKeyAttestationNonce(KeyAttestation $keyAttestation): void
    {
        $nonce = $keyAttestation->getNonce();

        if ($nonce === null) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The key attestation must carry a nonce claim obtained from the Nonce Endpoint.',
            );
        }

        if (!$this->nonceService->validateNonce($nonce)) {
            throw new CredentialRequestException(
                'invalid_nonce',
                'The c_nonce of the key attestation is invalid or expired.',
            );
        }
    }
}
