<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\VciProofTypeEnum;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\VerifiableCredentials\KeyAttestationVerifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciKeyAttestationRequirements;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Exceptions\X509TrustStoreException;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\VerifiableCredentials;
use SimpleSAML\OpenID\X509;
use SimpleSAML\OpenID\X509\CertificatePathValidator;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;

/**
 * Key attestations signed and chained for real, against certificates made when the tests run: a root, an issuing CA
 * under it, and the key storage component's certificate under that, which signs the attestations.
 */
#[CoversClass(KeyAttestationVerifier::class)]
#[AllowMockObjectsWithoutExpectations]
class KeyAttestationVerifierTest extends TestCase
{
    protected const string NONCE = 'nonce-value';

    protected const string ISO_HIGH = 'iso_18045_high';

    protected const string ISO_MODERATE = 'iso_18045_moderate';

    protected const string ISO_BASIC = 'iso_18045_basic';


    protected static PrivateKeyInfo $rootKey;

    protected static string $rootDer;

    protected static PrivateKeyInfo $issuingCaKey;

    protected static string $issuingCaDer;

    protected static PrivateKeyInfo $attesterKey;

    protected static string $attesterDer;

    protected static VerifiableCredentials $facade;

    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected ?string $trustAnchorsFilename = null;

    /** The key a proof is signed with, attested by default. */
    protected JWK $proofKey;

    /** @var list<string> */
    protected array $temporaryFiles = [];


    public static function setUpBeforeClass(): void
    {
        self::$rootKey = CertificateBuilder::ecKey();
        self::$rootDer = CertificateBuilder::root(self::$rootKey, 'CN=Key Attestation Root CA');
        self::$issuingCaKey = CertificateBuilder::ecKey();
        self::$issuingCaDer = CertificateBuilder::certificate(
            'CN=Key Attestation Issuing CA',
            self::$issuingCaKey,
            'CN=Key Attestation Root CA',
            self::$rootKey,
            CertificateBuilder::caExtensions(),
        );
        self::$attesterKey = CertificateBuilder::ecKey();
        self::$attesterDer = CertificateBuilder::certificate(
            'CN=Key Storage Component',
            self::$attesterKey,
            'CN=Key Attestation Issuing CA',
            self::$issuingCaKey,
            CertificateBuilder::leafExtensions(['https://wallet-provider.example.org']),
        );
        self::$facade = new VerifiableCredentials(
            supportedAlgorithms: new SupportedAlgorithms(
                new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256, SignatureAlgorithmEnum::ES384),
            ),
        );
    }


    protected function setUp(): void
    {
        $this->trustAnchorsFilename = $this->temporaryFile(CertificateBuilder::pem(self::$rootDer));
        $this->proofKey = JWKFactory::createECKey('P-256');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciKeyAttestationTrustAnchorsFilename')
            ->willReturnCallback(fn(): ?string => $this->trustAnchorsFilename);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function tearDown(): void
    {
        foreach ($this->temporaryFiles as $temporaryFile) {
            @unlink($temporaryFile);
        }
    }


    protected function temporaryFile(string $contents): string
    {
        $filename = (string)tempnam(sys_get_temp_dir(), 'key-attestation-anchors-');
        file_put_contents($filename, $contents);
        $this->temporaryFiles[] = $filename;

        return $filename;
    }


    protected function sut(?X509 $x509 = null): KeyAttestationVerifier
    {
        return new KeyAttestationVerifier(
            $this->moduleConfigMock,
            self::$facade,
            $x509 ?? new X509(),
            $this->loggerServiceMock,
        );
    }


    /**
     * A key attestation signed by the key storage component, its x5c the component's certificate and the issuing
     * CA's, attesting the proof key, with a nonce and both components, unless the arguments say otherwise. A claim
     * or header parameter given as null is left out.
     *
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $header
     * @return non-empty-string
     */
    protected function keyAttestation(array $claims = [], array $header = [], ?JWK $signingKey = null): string
    {
        $now = time();

        $payload = array_filter(
            [
                'iat' => $now,
                'exp' => $now + 300,
                'attested_keys' => [$this->proofKey->toPublic()->all()],
                'key_storage' => [self::ISO_HIGH],
                'user_authentication' => [self::ISO_MODERATE],
                'nonce' => self::NONCE,
                ...$claims,
            ],
            static fn(mixed $value): bool => $value !== null,
        );

        $header = array_filter(
            [
                'alg' => SignatureAlgorithmEnum::ES256->value,
                'typ' => 'key-attestation+jwt',
                'x5c' => [base64_encode(self::$attesterDer), base64_encode(self::$issuingCaDer)],
                ...$header,
            ],
            static fn(mixed $value): bool => $value !== null,
        );

        /** @var non-empty-string */
        return self::$facade->jwsSerializerManagerDecorator()->serialize(
            JwsSerializerEnum::Compact->value,
            self::$facade->jwsDecoratorBuilder()->fromData(
                new JwkDecorator(
                    $signingKey ?? JWKFactory::createFromKey(CertificateBuilder::privateKeyPem(self::$attesterKey)),
                ),
                SignatureAlgorithmEnum::ES256,
                $payload,
                $header,
            ),
        );
    }


    /**
     * @param non-empty-string $keyAttestation
     */
    protected function assertRefused(
        string $keyAttestation,
        string $message,
        VciProofTypeEnum $proofType = VciProofTypeEnum::Jwt,
        ?VciKeyAttestationRequirements $requirements = null,
    ): void {
        try {
            $this->sut()->verify($keyAttestation, $proofType, $requirements);
            $this->fail('The key attestation was accepted.');
        } catch (CredentialRequestException $credentialRequestException) {
            $this->assertSame('invalid_proof', $credentialRequestException->getErrorCode());
            $this->assertSame($message, $credentialRequestException->getMessage());
        }
    }


    public function testVerifiesAKeyAttestationOfAJwtProofChainedToATrustAnchor(): void
    {
        $keyAttestation = $this->sut()->verify(
            $this->keyAttestation(),
            VciProofTypeEnum::Jwt,
            new VciKeyAttestationRequirements([self::ISO_HIGH], [self::ISO_MODERATE]),
        );

        $this->assertTrue($keyAttestation->hasAttestedKey($this->proofKey->toPublic()->all()));
        $this->assertSame(self::NONCE, $keyAttestation->getNonce());
    }


    /**
     * Appendix D.1 requires `exp` only of an attestation used with the jwt proof type.
     */
    public function testVerifiesAnAttestationProofWithoutAnExpirationTime(): void
    {
        $keyAttestation = $this->sut()->verify(
            $this->keyAttestation(['exp' => null]),
            VciProofTypeEnum::Attestation,
            null,
        );

        $this->assertNull($keyAttestation->getExpirationTimeNumericDate());
    }


    public function testRefusesAKeyAttestationOfAJwtProofWithoutAnExpirationTime(): void
    {
        $this->assertRefused(
            $this->keyAttestation(['exp' => null]),
            'A key attestation in the key_attestation header of a jwt proof must carry an exp claim.',
        );
    }


    /**
     * Whatever the library refuses on parsing it: what Appendix D.1 requires of the JWT itself.
     *
     * @param array<string,mixed> $claims
     * @param array<string,mixed> $header
     */
    #[DataProvider('notAKeyAttestationProvider')]
    public function testRefusesWhatIsNotAValidKeyAttestation(array $claims, array $header): void
    {
        $this->assertRefused(
            $this->keyAttestation($claims, $header),
            'The key attestation could not be parsed, or is not a valid key attestation.',
        );
    }


    /**
     * @return array<string,array{array<string,mixed>,array<string,mixed>}>
     */
    public static function notAKeyAttestationProvider(): array
    {
        return [
            'another type' => [[], ['typ' => 'openid4vci-proof+jwt']],
            'no type' => [[], ['typ' => null]],
            'no attested keys' => [['attested_keys' => null], []],
            'no issue time' => [['iat' => null], []],
            'an expiration time which has passed' => [['exp' => time() - 3600], []],
            'a private key among the attested keys' => [
                ['attested_keys' => [JWKFactory::createECKey('P-256')->all()]],
                [],
            ],
            'a nonce which is not a string' => [['nonce' => 42], []],
            'a key storage which is not a list' => [['key_storage' => self::ISO_HIGH], []],
        ];
    }


    public function testRefusesSomethingWhichIsNotAJwtAtAll(): void
    {
        $this->assertRefused(
            'not-a-jwt',
            'The key attestation could not be parsed, or is not a valid key attestation.',
        );
    }


    /**
     * HAIP 1.0 section 4.5.1: the key which verifies a key attestation is in its x5c header. No other trust is
     * configured, so one which names its key otherwise is refused.
     */
    public function testRefusesAKeyAttestationWithoutACertificateChain(): void
    {
        $this->assertRefused(
            $this->keyAttestation([], ['x5c' => null, 'kid' => 'key-storage-1']),
            'The key attestation must carry the certificate chain of its signing key in an x5c header.',
        );
    }


    /**
     * RFC 7515 section 4.1.6 has x5c a JSON array. Decoded into PHP arrays, an object whose members are named 0 and 1
     * reads as a list, and would otherwise pass for one.
     */
    public function testRefusesACertificateChainWhichIsAJsonObject(): void
    {
        $this->assertRefused(
            $this->keyAttestation([], [
                'x5c' => (object)['0' => base64_encode(self::$attesterDer), '1' => base64_encode(self::$issuingCaDer)],
            ]),
            'The x5c header parameter of the key attestation must be a JSON array of certificates.',
        );
    }


    /**
     * @param callable(): list<string> $x5c
     */
    #[DataProvider('untrustedChainProvider')]
    public function testRefusesACertificateChainWhichDoesNotValidateAgainstTheTrustAnchors(callable $x5c): void
    {
        $this->assertRefused(
            $this->keyAttestation([], ['x5c' => $x5c()]),
            'The certificate chain of the key attestation does not validate against the trust anchors this issuer ' .
            'accepts key attestations under.',
        );
    }


    /**
     * @return array<string,array{callable(): list<string>}>
     */
    public static function untrustedChainProvider(): array
    {
        return [
            'a chain under another root' => [
                static function (): array {
                    $otherRootKey = CertificateBuilder::ecKey();
                    $otherIssuingCaKey = CertificateBuilder::ecKey();
                    $otherIssuingCa = CertificateBuilder::certificate(
                        'CN=Key Attestation Issuing CA',
                        $otherIssuingCaKey,
                        'CN=Key Attestation Root CA',
                        $otherRootKey,
                        CertificateBuilder::caExtensions(),
                    );

                    return [
                        base64_encode(CertificateBuilder::certificate(
                            'CN=Key Storage Component',
                            self::$attesterKey,
                            'CN=Key Attestation Issuing CA',
                            $otherIssuingCaKey,
                            CertificateBuilder::leafExtensions(),
                        )),
                        base64_encode($otherIssuingCa),
                    ];
                },
            ],
            // HAIP 1.0 section 4.5.1: "The X.509 certificate of the trust anchor MUST NOT be included".
            'a chain carrying the trust anchor' => [
                static fn(): array => [
                    base64_encode(self::$attesterDer),
                    base64_encode(self::$issuingCaDer),
                    base64_encode(self::$rootDer),
                ],
            ],
            // And "The X.509 certificate signing the key attestation MUST NOT be self-signed".
            'a self-signed certificate' => [
                static fn(): array => [
                    base64_encode(CertificateBuilder::certificate(
                        'CN=Key Storage Component',
                        self::$attesterKey,
                        'CN=Key Storage Component',
                        self::$attesterKey,
                        CertificateBuilder::leafExtensions(),
                    )),
                ],
            ],
            'a chain missing the issuing CA' => [
                static fn(): array => [base64_encode(self::$attesterDer)],
            ],
        ];
    }


    public function testRefusesAKeyAttestationNotSignedWithTheKeyOfItsCertificate(): void
    {
        $this->assertRefused(
            $this->keyAttestation([], [], JWKFactory::createECKey('P-256')),
            'The key attestation signature could not be verified with the key of its certificate.',
        );
    }


    /**
     * Section 12.2.4: for each component a configuration requires, the values it accepts, of which the attestation
     * has to state one; a component it does not require is not looked at.
     *
     * @param array<string,mixed> $claims
     */
    #[DataProvider('acceptedLevelProvider')]
    public function testAcceptsAKeyAttestationStatingALevelTheConfigurationAccepts(
        ?VciKeyAttestationRequirements $requirements,
        array $claims,
    ): void {
        $keyAttestation = $this->sut()->verify(
            $this->keyAttestation($claims),
            VciProofTypeEnum::Jwt,
            $requirements,
        );

        $this->assertSame(self::NONCE, $keyAttestation->getNonce());
    }


    /**
     * @return array<string,array{0:?object,1:array<string,mixed>}> The requirements, and the claims stated.
     */
    public static function acceptedLevelProvider(): array
    {
        return [
            'no requirements, and no levels stated' => [
                null,
                ['key_storage' => null, 'user_authentication' => null],
            ],
            'an attestation required without constraints, and no levels stated' => [
                new VciKeyAttestationRequirements(),
                ['key_storage' => null, 'user_authentication' => null],
            ],
            'one of the key storage values accepted' => [
                new VciKeyAttestationRequirements([self::ISO_HIGH, self::ISO_MODERATE]),
                ['key_storage' => [self::ISO_BASIC, self::ISO_MODERATE]],
            ],
            'the user authentication accepted, key storage not required' => [
                new VciKeyAttestationRequirements(null, [self::ISO_MODERATE]),
                ['key_storage' => null],
            ],
            'both accepted' => [
                new VciKeyAttestationRequirements([self::ISO_HIGH], [self::ISO_MODERATE]),
                [],
            ],
        ];
    }


    /**
     * @param array<string,mixed> $claims
     */
    #[DataProvider('refusedLevelProvider')]
    public function testRefusesAKeyAttestationNotStatingALevelTheConfigurationAccepts(
        VciKeyAttestationRequirements $requirements,
        array $claims,
        string $message,
    ): void {
        $this->assertRefused($this->keyAttestation($claims), $message, VciProofTypeEnum::Jwt, $requirements);
        $this->assertRefused($this->keyAttestation($claims), $message, VciProofTypeEnum::Attestation, $requirements);
    }


    /**
     * @return array<string,array{0:object,1:array<string,mixed>,2:string}> The requirements, the claims, the refusal.
     */
    public static function refusedLevelProvider(): array
    {
        $noKeyStorage = 'The key attestation states no key_storage, which this credential configuration requires.';
        $noUserAuthentication = 'The key attestation states no user_authentication, which this credential ' .
        'configuration requires.';

        return [
            'no key storage stated' => [
                new VciKeyAttestationRequirements([self::ISO_HIGH]),
                ['key_storage' => null],
                $noKeyStorage,
            ],
            'a key storage not accepted' => [
                new VciKeyAttestationRequirements([self::ISO_HIGH]),
                ['key_storage' => [self::ISO_MODERATE, self::ISO_BASIC]],
                'The key attestation states no key_storage value this credential configuration accepts.',
            ],
            'no user authentication stated' => [
                new VciKeyAttestationRequirements(null, [self::ISO_MODERATE]),
                ['user_authentication' => null],
                $noUserAuthentication,
            ],
            'a user authentication not accepted, though the key storage is' => [
                new VciKeyAttestationRequirements([self::ISO_HIGH], [self::ISO_HIGH]),
                [],
                'The key attestation states no user_authentication value this credential configuration accepts.',
            ],
            // Matched as written: the ISO levels are not ranked, since an ecosystem's own values need not be.
            'a higher level than the one accepted' => [
                new VciKeyAttestationRequirements([self::ISO_MODERATE]),
                ['key_storage' => [self::ISO_HIGH]],
                'The key attestation states no key_storage value this credential configuration accepts.',
            ],
        ];
    }


    /**
     * Appendices F.1 and F.3: this issuer has a Nonce Endpoint, so a key attestation carries a nonce, for whichever
     * proof type.
     */
    public function testRefusesAKeyAttestationWithoutANonce(): void
    {
        $message = 'The key attestation must carry a nonce claim obtained from the Nonce Endpoint.';

        $this->assertRefused($this->keyAttestation(['nonce' => null]), $message);
        $this->assertRefused($this->keyAttestation(['nonce' => null]), $message, VciProofTypeEnum::Attestation);
    }


    /**
     * The signature is checked before any claim is evaluated, so a forged attestation is refused as one whatever it
     * claims.
     */
    public function testChecksTheSignatureBeforeTheClaims(): void
    {
        $this->assertRefused(
            $this->keyAttestation(['exp' => null, 'nonce' => null], [], JWKFactory::createECKey('P-256')),
            'The key attestation signature could not be verified with the key of its certificate.',
        );
    }


    public function testRefusesToVerifyWithoutTrustAnchors(): void
    {
        $this->trustAnchorsFilename = null;

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(
            'set "' . ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME . '"',
        );

        $this->sut()->verify($this->keyAttestation(), VciProofTypeEnum::Jwt, null);
    }


    /**
     * @param callable(string): string $anchors The PEM file's contents, from the root's PEM.
     */
    #[DataProvider('unusableTrustAnchorsProvider')]
    public function testRefusesTrustAnchorsWhichCanNotBeUsed(callable $anchors): void
    {
        $this->trustAnchorsFilename = $this->temporaryFile($anchors(CertificateBuilder::pem(self::$rootDer)));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(
            'The trust anchors of "' . ModuleConfig::OPTION_VCI_KEY_ATTESTATION_TRUST_ANCHORS_FILENAME . '"',
        );

        $this->sut()->getTrustAnchors();
    }


    /**
     * @return array<string,array{callable(string): string}>
     */
    public static function unusableTrustAnchorsProvider(): array
    {
        return [
            'an empty file' => [static fn(string $rootPem): string => ''],
            'not PEM' => [static fn(string $rootPem): string => 'not a certificate'],
            'a CA which is not self-signed' => [
                static fn(string $rootPem): string => CertificateBuilder::pem(self::$issuingCaDer),
            ],
            // An anchor outside its validity period validates no path, so every key attestation would be refused,
            // as if the wallets were at fault.
            'a root which has expired' => [
                static fn(string $rootPem): string => CertificateBuilder::pem(
                    CertificateBuilder::root(CertificateBuilder::ecKey(), 'CN=Expired Root CA', '-1 minute'),
                ),
            ],
        ];
    }


    /**
     * A root which has expired beside one which is valid, as during a rollover, does no harm.
     */
    public function testKeepsARootWhichHasExpiredBesideAValidOne(): void
    {
        $this->trustAnchorsFilename = $this->temporaryFile(
            CertificateBuilder::pem(
                CertificateBuilder::root(CertificateBuilder::ecKey(), 'CN=Expired Root CA', '-1 minute'),
                self::$rootDer,
            ),
        );

        $sut = $this->sut();

        $this->assertCount(2, $sut->getTrustAnchors());
        $this->assertSame(
            self::NONCE,
            $sut->verify($this->keyAttestation(), VciProofTypeEnum::Jwt, null)->getNonce(),
        );
    }


    public function testRefusesTrustAnchorsWhichCanNotBeRead(): void
    {
        $this->trustAnchorsFilename = sys_get_temp_dir() . '/no-such-key-attestation-anchors-' .
        bin2hex(random_bytes(4));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('can not be read');

        $this->sut()->getTrustAnchors();
    }


    public function testReadsTheTrustAnchorsOnce(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->expects($this->once())->method('getVciKeyAttestationTrustAnchorsFilename')
            ->willReturn($this->trustAnchorsFilename);

        $sut = $this->sut();
        $trustAnchors = $sut->getTrustAnchors();
        $sut->verify($this->keyAttestation(), VciProofTypeEnum::Jwt, null);

        $this->assertSame($trustAnchors, $sut->getTrustAnchors());
        $this->assertCount(1, $trustAnchors);
    }


    /**
     * A trust store which can not be set up is this issuer's fault, not the wallet's, so it is not answered as an
     * invalid proof.
     */
    public function testLeavesATrustStoreWhichCanNotBeSetUpToTheCaller(): void
    {
        $realX509 = new X509();
        $pathValidatorMock = $this->createMock(CertificatePathValidator::class);
        $pathValidatorMock->method('validate')
            ->willThrowException(new X509TrustStoreException('No temporary directory.'));
        $x509Mock = $this->createMock(X509::class);
        $x509Mock->method('certificateFactory')->willReturn($realX509->certificateFactory());
        $x509Mock->method('certificatePathValidator')->willReturn($pathValidatorMock);

        $this->expectException(X509TrustStoreException::class);

        $this->sut($x509Mock)->verify($this->keyAttestation(), VciProofTypeEnum::Jwt, null);
    }
}
