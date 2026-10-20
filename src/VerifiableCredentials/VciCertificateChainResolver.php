<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain;
use SimpleSAML\OpenID\Exceptions\X509Exception;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\X509;
use Throwable;

/**
 * The certificate chain of a Verifiable Credential Issuance signing key, validated, for the `x5c` header of what the
 * key signs: credentials (HAIP 1.0 section 6.1.1) and Status List Tokens (section 6.1).
 *
 * A chain is validated whenever it is asked for, once per request, not once when it is configured: a chain validates
 * only for as long as each of its certificates does, so one which has expired is refused here like one which never
 * validated, and nothing is signed which carries it. What is checked is what a verifier checks, against the trust
 * anchors of ModuleConfig::OPTION_VCI_ISSUER_TRUST_ANCHORS_FILENAME: path validation, with each certificate's
 * validity, the CA constraints, path lengths and critical extensions, no trust anchor in the chain and no self-signed
 * certificate (HAIP 1.0 sections 6.1 and 6.1.1), and the leaf holding the key pair's public key, without which the
 * chain would name a key the signature was not made with.
 *
 * Every fault is a ConfigurationError naming the key, since only the configuration can correct it.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\VciCertificateChainResolverTest
 */
class VciCertificateChainResolver
{
    /**
     * @var array<string,?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain>
     */
    protected array $resolved = [];

    /**
     * @var ?non-empty-list<\SimpleSAML\OpenID\X509\Certificate>
     */
    protected ?array $trustAnchors = null;


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly X509 $x509,
    ) {
    }


    /**
     * The chain of the key pair, validated now, or null when the key pair has none.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function resolveFor(SignatureKeyPair $signatureKeyPair): ?VciCertificateChain
    {
        $keyId = $signatureKeyPair->getKeyPair()->getKeyId();

        if (array_key_exists($keyId, $this->resolved)) {
            return $this->resolved[$keyId];
        }

        $filename = $this->moduleConfig->getVciSignatureCertificateChainFilenames()[$keyId] ?? null;

        if ($filename === null) {
            return $this->resolved[$keyId] = null;
        }

        $trustAnchors = $this->getTrustAnchors();

        try {
            $chain = $this->x509->certificateFactory()->chainFromPem($this->read($filename));

            /** @var array<string,mixed> $publicKey A JWK's members, by their names. */
            $publicKey = $signatureKeyPair->getKeyPair()->getPublicKey()->jwk()->all();

            if (!$chain->getLeaf()->hasPublicKey($publicKey)) {
                throw new X509Exception('Its first certificate does not hold the public key of the key pair.');
            }

            $validatedPath = $this->x509->certificatePathValidator()->validate($chain, $trustAnchors);
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                sprintf(
                    'The certificate chain of the VCI signature key "%s" (%s) can not be used: %s',
                    $keyId,
                    $filename,
                    $throwable->getMessage(),
                ),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }

        return $this->resolved[$keyId] = new VciCertificateChain($chain, $validatedPath);
    }


    /**
     * The trust anchors the chains are validated against, each a self-signed CA certificate.
     *
     * @return non-empty-list<\SimpleSAML\OpenID\X509\Certificate>
     * @throws \SimpleSAML\Error\ConfigurationError When none are configured, which is a fault only once a key pair
     * has a chain, or when they can not be read or can not be trust anchors.
     */
    public function getTrustAnchors(): array
    {
        if ($this->trustAnchors !== null) {
            return $this->trustAnchors;
        }

        $filename = $this->moduleConfig->getVciIssuerTrustAnchorsFilename();

        if ($filename === null) {
            throw new ConfigurationError(
                sprintf(
                    'A certificate chain is configured under "%s", but there are no trust anchors to validate it ' .
                    'against: set "%s".',
                    ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS,
                    ModuleConfig::OPTION_VCI_ISSUER_TRUST_ANCHORS_FILENAME,
                ),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }

        try {
            $trustAnchors = $this->x509->certificateFactory()->bundleFromPem($this->read($filename));
            $this->x509->certificatePathValidator()->enforceTrustAnchors($trustAnchors);
        } catch (Throwable $throwable) {
            throw new ConfigurationError(
                sprintf(
                    'The trust anchors of "%s" (%s) can not be used: %s',
                    ModuleConfig::OPTION_VCI_ISSUER_TRUST_ANCHORS_FILENAME,
                    $filename,
                    $throwable->getMessage(),
                ),
                ModuleConfig::DEFAULT_FILE_NAME,
            );
        }

        return $this->trustAnchors = $trustAnchors;
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\X509Exception
     */
    protected function read(string $filename): string
    {
        $contents = is_readable($filename) ? file_get_contents($filename) : false;

        if (!is_string($contents)) {
            throw new X509Exception(sprintf('The file %s can not be read.', $filename));
        }

        return $contents;
    }
}
