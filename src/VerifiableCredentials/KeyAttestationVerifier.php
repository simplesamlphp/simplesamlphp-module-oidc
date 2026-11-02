<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Exceptions\X509Exception;
use SimpleSAML\OpenID\Exceptions\X509TrustStoreException;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\VerifiableCredentials\KeyAttestation;
use SimpleSAML\OpenID\X509;
use SimpleSAML\OpenID\X509\Certificate;
use stdClass;
use Throwable;

/**
 * Verifies a key attestation (OpenID4VCI 1.0 Appendix D.1) sent with a Credential Request: in the `key_attestation`
 * header of a `jwt` proof (Appendix F.1), or as an `attestation` proof (Appendix F.3).
 *
 * What is checked here is what holds of the attestation on its own: what the library checks on parsing it (`typ`,
 * an asymmetric `alg`, an integer `iat` not ahead, `attested_keys` public keys, an `exp` which has not passed, the
 * shapes of the other claims); its signature, by the key of an `x5c` certificate chain which validates against the
 * trust anchors of ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME, the anchors not in the chain
 * and its first certificate not self-signed (HAIP 1.0 section 4.5.1); an `exp` when it comes with a `jwt` proof
 * (Appendix D.1); the levels the credential configuration accepts (section 12.2.4); and that it carries a nonce,
 * since this issuer has a Nonce Endpoint (Appendices F.1, F.3). An attestation trusted any other way (a `kid`, a
 * `trust_chain`) is refused: no other trust is configured.
 *
 * What depends on the request stays with the caller (OpenId4VciProofValidator): which `alg` is advertised, whether
 * the proof's key is one of the attested keys, and whether the nonce is one this issuer gave, which it asks of
 * NonceService once everything else holds, so that `invalid_nonce` is only ever said of an otherwise sound proof.
 *
 * Not checked: revocation, of the certificates or through the attestation's `status` (D37 (a) of the HAIP plan).
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\KeyAttestationVerifierTest
 */
class KeyAttestationVerifier
{
    /**
     * @var ?non-empty-list<\SimpleSAML\OpenID\X509\Certificate>
     */
    protected ?array $trustAnchors = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly VerifiableCredentials $verifiableCredentials,
        protected readonly X509 $x509,
        protected readonly LoggerService $loggerService,
    ) {
    }


    /**
     * The trust anchors key attestations are validated against, each a self-signed CA certificate.
     *
     * At least one has to be valid now. An anchor outside its validity period validates no path, so with none valid
     * every key attestation would be refused as the wallet's fault; refused here as the issuer's instead. One which
     * has expired beside a valid one, as during a rollover, does no harm, and stays.
     *
     * @return non-empty-list<\SimpleSAML\OpenID\X509\Certificate>
     * @throws \SimpleSAML\Error\ConfigurationError When none are configured, or when they can not be read, can not
     * be trust anchors or are none of them valid now: the issuer's fault, not the wallet's.
     */
    public function getTrustAnchors(): array
    {
        if ($this->trustAnchors !== null) {
            return $this->trustAnchors;
        }

        $filename = $this->moduleConfig->getVciKeyAttestationTrustAnchorsFilename();

        if ($filename === null) {
            throw new ConfigurationError(
                sprintf(
                    'A credential configuration takes key attestations under "%s", but there are no trust anchors ' .
                    'to validate them against: set "%s".',
                    ModuleConfig::OPTION_VCI_CREDENTIAL_PROOF_TYPES,
                    ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME,
                ),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }

        try {
            $contents = is_readable($filename) ? file_get_contents($filename) : false;

            if (!is_string($contents)) {
                throw new X509Exception(sprintf('The file %s can not be read.', $filename));
            }

            $trustAnchors = $this->x509->certificateFactory()->bundleFromPem($contents);
            $this->x509->certificatePathValidator()->enforceTrustAnchors($trustAnchors);

            $now = time();
            $validTrustAnchors = array_filter(
                $trustAnchors,
                static fn(Certificate $trustAnchor): bool => $trustAnchor->isValidAt($now),
            );

            if ($validTrustAnchors === []) {
                throw new X509Exception('None of them is valid now.');
            }
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                sprintf(
                    'The trust anchors of "%s" (%s) can not be used: %s',
                    ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME,
                    $filename,
                    $throwable->getMessage(),
                ),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }

        return $this->trustAnchors = $trustAnchors;
    }


    /**
     * The key attestation, verified as the class description has it.
     *
     * @param non-empty-string $keyAttestationJwt
     * @param \SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum $proofType The proof type it came with: with `jwt`
     * it has to carry an `exp`.
     * @param ?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements $requirements What the
     * proof type requires of the levels it states, or null for nothing.
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException When it is refused (`invalid_proof`).
     * @throws \SimpleSAML\Error\ConfigurationError When the trust anchors can not be used.
     * @throws \SimpleSAML\OpenID\Exceptions\X509TrustStoreException When the path validation can not run.
     */
    public function verify(
        string $keyAttestationJwt,
        VciProofTypeEnum $proofType,
        ?VciKeyAttestationRequirements $requirements,
    ): KeyAttestation {
        $trustAnchors = $this->getTrustAnchors();

        try {
            $keyAttestation = $this->verifiableCredentials->keyAttestationFactory()->fromToken($keyAttestationJwt);
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key attestation could not be parsed, or is not a valid one.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The key attestation could not be parsed, or is not a valid key attestation.',
            );
        }

        try {
            $x5c = $keyAttestation->getX509CertificateChain();
        } catch (Throwable) {
            // Refused on parsing already, which reads x5c too.
            $x5c = null;
        }

        if ($x5c === null) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The key attestation must carry the certificate chain of its signing key in an x5c header.',
            );
        }

        // RFC 7515 section 4.1.6: a JSON array. Read from the header as sent, since decoded into PHP arrays an object
        // whose members are named 0, 1 and so on reads as a list too.
        if (!$this->protectedHeaderHoldsJsonArray($keyAttestationJwt, ClaimsEnum::X5c->value)) {
            throw new CredentialRequestException(
                'invalid_proof',
                'The x5c header parameter of the key attestation must be a JSON array of certificates.',
            );
        }

        try {
            $validatedPath = $this->x509->certificatePathValidator()->validate(
                $this->x509->certificateFactory()->chainFromX5c($x5c),
                $trustAnchors,
            );
        } catch (X509TrustStoreException $x509TrustStoreException) {
            throw $x509TrustStoreException;
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key attestation certificate chain does not validate against the key attestation trust anchors.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The certificate chain of the key attestation does not validate against the trust anchors this ' .
                'issuer accepts key attestations under.',
            );
        }

        try {
            $keyAttestation->verifyWithX509CertificatePath($validatedPath);
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key attestation signature could not be verified.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException(
                'invalid_proof',
                'The key attestation signature could not be verified with the key of its certificate.',
            );
        }

        // Every claim is read only now that the signature holds, by the getters which parsing has run once already.
        try {
            // Appendix D.1: "MUST be present if the attestation is used with the JWT proof type".
            if ($proofType === VciProofTypeEnum::Jwt && $keyAttestation->getExpirationTimeNumericDate() === null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'A key attestation in the key_attestation header of a jwt proof must carry an exp claim.',
                );
            }

            if ($requirements !== null) {
                $this->enforceAcceptedLevel(
                    $keyAttestation->getKeyStorage(),
                    $requirements->getKeyStorage(),
                    ClaimsEnum::KeyStorage->value,
                );
                $this->enforceAcceptedLevel(
                    $keyAttestation->getUserAuthentication(),
                    $requirements->getUserAuthentication(),
                    ClaimsEnum::UserAuthentication->value,
                );
            }

            // Appendices F.1 and F.3, for an issuer with a Nonce Endpoint; whether it is one this issuer gave is the
            // caller's to ask last.
            if ($keyAttestation->getNonce() === null) {
                throw new CredentialRequestException(
                    'invalid_proof',
                    'The key attestation must carry a nonce claim obtained from the Nonce Endpoint.',
                );
            }
        } catch (CredentialRequestException $credentialRequestException) {
            $this->loggerService->warning(
                'Key attestation refused.',
                ['reason' => $credentialRequestException->getMessage()],
            );

            throw $credentialRequestException;
        } catch (Throwable $throwable) {
            $this->loggerService->warning(
                'Key attestation could not be read.',
                ['error' => $throwable->getMessage()],
            );

            throw new CredentialRequestException('invalid_proof', 'The key attestation could not be read.');
        }

        $this->loggerService->debug('Key attestation verified.');

        return $keyAttestation;
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
     * Refuse an attestation which does not state, for a component the configuration requires, one of the values it
     * accepts (section 12.2.4: the values "accepted by the Credential Issuer").
     *
     * @param ?non-empty-list<non-empty-string> $stated
     * @param ?non-empty-list<non-empty-string> $accepted
     * @throws \SimpleSAML\Module\oidc\Exceptions\CredentialRequestException
     */
    protected function enforceAcceptedLevel(?array $stated, ?array $accepted, string $component): void
    {
        if ($accepted === null) {
            return;
        }

        if ($stated === null) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'The key attestation states no %s, which this credential configuration requires.',
                    $component,
                ),
            );
        }

        // The values accepted are published in the configuration's key_attestations_required, and not repeated here:
        // an ecosystem's own values may hold characters an error_description may not.
        if (array_intersect($stated, $accepted) === []) {
            throw new CredentialRequestException(
                'invalid_proof',
                sprintf(
                    'The key attestation states no %s value this credential configuration accepts.',
                    $component,
                ),
            );
        }
    }
}
