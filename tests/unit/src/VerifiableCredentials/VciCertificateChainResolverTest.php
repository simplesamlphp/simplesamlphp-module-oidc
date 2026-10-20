<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciCertificateChainResolver;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\X509;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;

#[CoversClass(VciCertificateChainResolver::class)]
#[UsesClass(VciCertificateChain::class)]
#[AllowMockObjectsWithoutExpectations]
class VciCertificateChainResolverTest extends TestCase
{
    protected const string KEY_ID = 'vci-signing-key-01';

    protected const string ROOT = 'CN=Test Root CA';

    protected const string INTERMEDIATE = 'CN=Test Intermediate CA';

    protected const string LEAF = 'CN=Test Credential Issuer';


    protected static PrivateKeyInfo $rootKey;

    protected static PrivateKeyInfo $intermediateKey;

    protected static PrivateKeyInfo $leafKey;

    protected string $directory;

    /**
     * The trust anchor of most tests, made once per test: ECDSA signatures differ each time, so a second one would
     * be another certificate.
     */
    protected string $root;


    public static function setUpBeforeClass(): void
    {
        self::$rootKey = CertificateBuilder::ecKey();
        self::$intermediateKey = CertificateBuilder::ecKey();
        self::$leafKey = CertificateBuilder::ecKey();
    }


    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir() . '/oidc-vci-chain-test-' . bin2hex(random_bytes(8));
        mkdir($this->directory, 0700);

        $this->root = $this->rootCertificate();
    }


    protected function tearDown(): void
    {
        foreach (glob($this->directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($this->directory);
    }


    /**
     * @param array<string,non-empty-string> $chainFilenames
     */
    protected function moduleConfig(array $chainFilenames, ?string $trustAnchorsFilename): MockObject&ModuleConfig
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciSignatureCertificateChainFilenames')->willReturn($chainFilenames);
        $moduleConfigMock->method('getVciIssuerTrustAnchorsFilename')->willReturn($trustAnchorsFilename);

        return $moduleConfigMock;
    }


    protected function sut(ModuleConfig $moduleConfig): VciCertificateChainResolver
    {
        return new VciCertificateChainResolver($moduleConfig, new X509($this->directory));
    }


    protected function signatureKeyPair(PrivateKeyInfo $key): SignatureKeyPair
    {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn(self::KEY_ID);
        $keyPairMock->method('getPublicKey')->willReturn(
            (new JwkDecoratorFactory())->fromData(CertificateBuilder::publicJwk($key)),
        );

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        return $signatureKeyPairMock;
    }


    /**
     * @return non-empty-string
     */
    protected function write(string $name, string $contents): string
    {
        $filename = $this->directory . '/' . $name;
        file_put_contents($filename, $contents);

        return $filename;
    }


    protected function rootCertificate(string $notAfter = '+1 year'): string
    {
        return CertificateBuilder::root(self::$rootKey, self::ROOT, $notAfter);
    }


    protected function intermediateCertificate(string $notAfter = '+30 days'): string
    {
        return CertificateBuilder::certificate(
            self::INTERMEDIATE,
            self::$intermediateKey,
            self::ROOT,
            self::$rootKey,
            CertificateBuilder::caExtensions(),
            '-1 hour',
            $notAfter,
        );
    }


    protected function leafCertificate(string $notBefore = '-1 hour', string $notAfter = '+7 days'): string
    {
        return CertificateBuilder::certificate(
            self::LEAF,
            self::$leafKey,
            self::INTERMEDIATE,
            self::$intermediateKey,
            CertificateBuilder::leafExtensions(['https://issuer.example.org'], ['issuer.example.org']),
            $notBefore,
            $notAfter,
        );
    }


    /**
     * A chain of the given certificates, under the root as the one trust anchor.
     */
    protected function sutWithChain(string ...$ders): VciCertificateChainResolver
    {
        return $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write('chain.pem', CertificateBuilder::pem(...$ders))],
            $this->write('anchors.pem', CertificateBuilder::pem($this->root)),
        ));
    }


    public function testAKeyPairWithoutAChainHasNoneAndNeedsNoTrustAnchors(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciSignatureCertificateChainFilenames')->willReturn([]);
        $moduleConfigMock->expects($this->never())->method('getVciIssuerTrustAnchorsFilename');

        $this->assertNull($this->sut($moduleConfigMock)->resolveFor($this->signatureKeyPair(self::$leafKey)));
    }


    /**
     * The header carries the chain as configured: the trust anchor is in the validated path, never in `x5c`
     * (HAIP 1.0 section 6.1.1).
     */
    public function testAChainIsValidatedAndCarriedWithoutItsTrustAnchor(): void
    {
        $leaf = $this->leafCertificate();
        $intermediate = $this->intermediateCertificate();

        $chain = $this->sutWithChain($leaf, $intermediate)->resolveFor($this->signatureKeyPair(self::$leafKey));

        $this->assertInstanceOf(VciCertificateChain::class, $chain);
        $this->assertSame([base64_encode($leaf), base64_encode($intermediate)], $chain->getX5c());
        $this->assertSame($leaf, $chain->getLeaf()->getDer());
        $this->assertSame($this->root, $chain->getTrustAnchor()->getDer());
        $this->assertCount(3, $chain->getValidatedPath());
    }


    /**
     * An intermediate which expires before the leaf ends the chain's validity.
     */
    public function testTheChainEndsWithTheEarliestEndOfValidityOfAnIntermediate(): void
    {
        $intermediate = $this->intermediateCertificate('+2 days');

        $chain = $this->sutWithChain($this->leafCertificate(), $intermediate)
            ->resolveFor($this->signatureKeyPair(self::$leafKey));

        $this->assertNotNull($chain);
        $this->assertSame($chain->getChain()->getCertificates()[1]->getNotAfter(), $chain->getEarliestNotAfter());
        $this->assertLessThan($chain->getLeaf()->getNotAfter(), $chain->getEarliestNotAfter());
    }


    /**
     * The trust anchor counts too, though it is not in the chain a credential carries.
     */
    public function testTheChainEndsWithTheEarliestEndOfValidityOfTheTrustAnchor(): void
    {
        $root = $this->rootCertificate('+3 days');

        $chain = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write(
                'chain.pem',
                CertificateBuilder::pem($this->leafCertificate(), $this->intermediateCertificate()),
            )],
            $this->write('anchors.pem', CertificateBuilder::pem($root)),
        ))->resolveFor($this->signatureKeyPair(self::$leafKey));

        $this->assertNotNull($chain);
        $this->assertSame($chain->getTrustAnchor()->getNotAfter(), $chain->getEarliestNotAfter());
        $this->assertLessThan($chain->getLeaf()->getNotAfter(), $chain->getEarliestNotAfter());
    }


    /**
     * Each request validates a key's chain once, however often it signs.
     */
    public function testAChainIsResolvedOncePerKey(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->expects($this->once())
            ->method('getVciSignatureCertificateChainFilenames')
            ->willReturn([self::KEY_ID => $this->write(
                'chain.pem',
                CertificateBuilder::pem($this->leafCertificate(), $this->intermediateCertificate()),
            )]);
        $moduleConfigMock->expects($this->once())
            ->method('getVciIssuerTrustAnchorsFilename')
            ->willReturn($this->write('anchors.pem', CertificateBuilder::pem($this->root)));

        $sut = $this->sut($moduleConfigMock);
        $signatureKeyPair = $this->signatureKeyPair(self::$leafKey);

        $this->assertSame($sut->resolveFor($signatureKeyPair), $sut->resolveFor($signatureKeyPair));
    }


    public function testAChainWithoutTrustAnchorsIsRefused(): void
    {
        $sut = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write(
                'chain.pem',
                CertificateBuilder::pem($this->leafCertificate(), $this->intermediateCertificate()),
            )],
            null,
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_ISSUER_TRUST_ANCHORS_FILENAME);

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }


    /**
     * A chain naming a key the signature was not made with would have a verifier check the wrong key.
     */
    public function testAChainWhoseLeafHoldsAnotherKeyIsRefused(): void
    {
        $sut = $this->sutWithChain($this->leafCertificate(), $this->intermediateCertificate());

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('"' . self::KEY_ID . '"');
        $this->expectExceptionMessage('does not hold the public key of the key pair');

        $sut->resolveFor($this->signatureKeyPair(CertificateBuilder::ecKey()));
    }


    /**
     * HAIP 1.0 section 6.1.1: "The X.509 certificate of the trust anchor MUST NOT be included in the x5c JOSE
     * header". A trust anchor is self-signed, which is what the library refuses it for first.
     */
    public function testAChainCarryingItsTrustAnchorIsRefused(): void
    {
        $sut = $this->sutWithChain($this->leafCertificate(), $this->intermediateCertificate(), $this->root);

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('"' . self::KEY_ID . '"');
        $this->expectExceptionMessage('Certificate 2 of the chain (cn=Test Root CA) is self-issued or self-signed.');

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }


    public function testAChainWithAnExpiredLeafIsRefused(): void
    {
        $sut = $this->sutWithChain($this->leafCertificate('-2 days', '-1 day'), $this->intermediateCertificate());

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('"' . self::KEY_ID . '"');
        $this->expectExceptionMessage('outside the validity period');

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }


    public function testAChainUnderAnotherRootIsRefused(): void
    {
        $sut = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write(
                'chain.pem',
                CertificateBuilder::pem($this->leafCertificate(), $this->intermediateCertificate()),
            )],
            $this->write(
                'anchors.pem',
                CertificateBuilder::pem(CertificateBuilder::root(CertificateBuilder::ecKey(), 'CN=Other Root CA')),
            ),
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('"' . self::KEY_ID . '"');
        $this->expectExceptionMessage('not issued by any of the trust anchors');

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }


    /**
     * While a root is being replaced, both are trust anchors, and a chain validates under either.
     */
    public function testAChainValidatesUnderAnyOfTheTrustAnchors(): void
    {
        $chain = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write(
                'chain.pem',
                CertificateBuilder::pem($this->leafCertificate(), $this->intermediateCertificate()),
            )],
            $this->write('anchors.pem', CertificateBuilder::pem(
                CertificateBuilder::root(CertificateBuilder::ecKey(), 'CN=Next Root CA'),
                $this->root,
            )),
        ))->resolveFor($this->signatureKeyPair(self::$leafKey));

        $this->assertNotNull($chain);
        $this->assertSame($this->root, $chain->getTrustAnchor()->getDer());
    }


    /**
     * PHP's path validation takes no flag which would let an intermediate be a trust anchor, so one is refused
     * where it is configured.
     */
    public function testATrustAnchorWhichIsNotSelfSignedIsRefused(): void
    {
        $sut = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->write('chain.pem', CertificateBuilder::pem($this->leafCertificate()))],
            $this->write('anchors.pem', CertificateBuilder::pem($this->intermediateCertificate())),
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(
            'The trust anchors of "' . ModuleConfig::OPTION_VCI_ISSUER_TRUST_ANCHORS_FILENAME . '"',
        );

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }


    public function testAChainWhichCanNotBeReadIsRefused(): void
    {
        $sut = $this->sut($this->moduleConfig(
            [self::KEY_ID => $this->directory . '/missing.pem'],
            $this->write('anchors.pem', CertificateBuilder::pem($this->root)),
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('"' . self::KEY_ID . '"');
        $this->expectExceptionMessage('can not be read');

        $sut->resolveFor($this->signatureKeyPair(self::$leafKey));
    }
}
