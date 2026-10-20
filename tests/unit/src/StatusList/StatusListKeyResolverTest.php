<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\StatusList\StatusListKeyResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciCertificateChain;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciCertificateChainResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(StatusListKeyResolver::class)]
#[AllowMockObjectsWithoutExpectations]
class StatusListKeyResolverTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $signatureKeyPairBagMock;

    protected MockObject $vciCertificateChainResolverMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->vciCertificateChainResolverMock = $this->createMock(VciCertificateChainResolver::class);
        $this->signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')
            ->willReturn($this->signatureKeyPairBagMock);
    }


    protected function sut(): StatusListKeyResolver
    {
        return new StatusListKeyResolver($this->moduleConfigMock, $this->vciCertificateChainResolverMock);
    }


    protected function buildSignatureKeyPair(string $keyId): MockObject
    {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn($keyId);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);

        return $signatureKeyPairMock;
    }


    /**
     * A new list has to be bound to the same key credentials are being signed with, otherwise a
     * credential would be signed with one key while the Status List Token its holder is told to check
     * is signed with another. It is the same accessor issuance uses, which is what makes that hold.
     */
    public function testCurrentKeyIsTheActiveCredentialSigningKey(): void
    {
        $activeSignatureKeyPair = $this->buildSignatureKeyPair('vci-01');
        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')->willReturn($activeSignatureKeyPair);

        $this->assertSame($activeSignatureKeyPair, $this->sut()->getCurrent());
        $this->assertSame('vci-01', $this->sut()->getCurrentKeyId());
    }


    /**
     * Reported as a Status List failure rather than as whatever the configuration layer threw, since
     * the caller's problem is that it can not sign a list.
     */
    public function testCurrentKeyFailureIsReportedAsAStatusListFailure(): void
    {
        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')
            ->willThrowException(new OpenIdException('Signature key pair is not set.'));

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('can not be signed');

        $this->sut()->getCurrent();
    }


    /**
     * An existing list is re-signed from the key it was created with, which may no longer be the one
     * signing now. Resolving by key ID is what lets a list outlive a key rollover.
     */
    public function testAListIsResolvedToTheKeyItWasCreatedWith(): void
    {
        $retiredSignatureKeyPair = $this->buildSignatureKeyPair('vci-retired');
        $this->signatureKeyPairBagMock->method('getByKeyId')
            ->with('vci-retired')
            ->willReturn($retiredSignatureKeyPair);

        $this->assertSame($retiredSignatureKeyPair, $this->sut()->getByKeyId('vci-retired'));
    }


    /**
     * Falling back to the current key here would produce a token signed with a key the credential's
     * holder never bound to, and would do so while looking like success.
     */
    public function testRefusesToSubstituteAnotherKeyForOneWhichIsGone(): void
    {
        $this->signatureKeyPairBagMock->method('getByKeyId')->with('vci-discarded')->willReturn(null);
        $this->moduleConfigMock->expects($this->never())->method('getActiveVciSignatureKeyPair');

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('vci-discarded');

        $this->sut()->getByKeyId('vci-discarded');
    }


    /**
     * The chain of the key a list is signed with, as the resolver validated it.
     */
    public function testTheCertificateChainOfAKeyIsTheOneItsResolverValidated(): void
    {
        $signatureKeyPair = $this->buildSignatureKeyPair('vci-01');
        $certificateChain = $this->createMock(VciCertificateChain::class);
        $this->vciCertificateChainResolverMock->expects($this->once())->method('resolveFor')
            ->with($signatureKeyPair)
            ->willReturn($certificateChain);

        $this->assertSame($certificateChain, $this->sut()->getCertificateChainFor($signatureKeyPair));
    }


    /**
     * A token under the `x509` key profile names its key by its chain alone, so a key without one can not sign one.
     */
    public function testAKeyWithoutACertificateChainCanNotSignUnderTheX509KeyProfile(): void
    {
        $this->vciCertificateChainResolverMock->method('resolveFor')->willReturn(null);

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The key "vci-01" has no certificate chain');

        $this->sut()->getCertificateChainFor($this->buildSignatureKeyPair('vci-01'));
    }


    public function testAKeyWhoseCertificateChainCanNotBeUsedCanNotSignUnderTheX509KeyProfile(): void
    {
        $this->vciCertificateChainResolverMock->method('resolveFor')
            ->willThrowException(new ConfigurationError('The certificate chain has expired.'));

        $this->expectException(StatusListException::class);
        $this->expectExceptionMessage('The certificate chain of the key "vci-01" can not be used');
        $this->expectExceptionMessage('The certificate chain has expired.');

        $this->sut()->getCertificateChainFor($this->buildSignatureKeyPair('vci-01'));
    }
}
