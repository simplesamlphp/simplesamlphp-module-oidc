<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\DidFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Did\DidUrl;
use SimpleSAML\OpenID\Did\Factories\DidDocumentFactory;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;

#[CoversClass(VciIssuerIdentityResolver::class)]
#[AllowMockObjectsWithoutExpectations]
class VciIssuerIdentityResolverTest extends TestCase
{
    protected const string ISSUER = 'https://issuer.example.org';

    protected const string DID_JWK = 'did:jwk:eyJrdHkiOiJFQyJ9';

    protected const string DID_WEB = 'did:web:example.org';

    protected const string KEY_ID = 'vci-signing-key-01';


    protected MockObject $moduleConfigMock;

    protected MockObject $didFactoryMock;

    protected MockObject $didMock;

    protected MockObject $didJwkResolverMock;

    protected MockObject $didDocumentFactoryMock;

    protected SignatureKeyPair $signatureKeyPair;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);

        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn(self::DID_JWK);

        $this->didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $this->didDocumentFactoryMock->method('verificationMethodIdFor')->willReturnCallback(
            static fn(DidUrl $did, string $keyId): DidUrl => new DidUrl($did->getDid() . '#' . $keyId),
        );

        $this->didMock = $this->createMock(Did::class);
        $this->didMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);
        $this->didMock->method('didDocumentFactory')->willReturn($this->didDocumentFactoryMock);

        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('build')->willReturn($this->didMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn(self::KEY_ID);
        $keyPairMock->method('getPublicKey')->willReturn(
            (new JwkDecoratorFactory())->fromData(['kty' => 'EC']),
        );

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->signatureKeyPair = $signatureKeyPairMock;
    }


    protected function sut(): VciIssuerIdentityResolver
    {
        return new VciIssuerIdentityResolver($this->moduleConfigMock, $this->didFactoryMock);
    }


    public function testDidJwkNamesTheKeyByTheFragmentTheMethodDefines(): void
    {
        $identity = $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk),
            $this->signatureKeyPair,
        );

        $this->assertSame(VciIssuerIdentifierModeEnum::DidJwk, $identity->getMode());
        $this->assertSame(self::DID_JWK, $identity->getIssuer());
        $this->assertSame(self::DID_JWK . '#0', $identity->getKeyId());
    }


    /**
     * The key identifier has to be minted by the same code which builds the published document, or a
     * credential could name a verification method the document does not carry.
     */
    public function testDidWebNamesTheKeyThroughTheDocumentFactory(): void
    {
        $this->didDocumentFactoryMock->expects($this->once())->method('verificationMethodIdFor');

        $identity = $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB),
            $this->signatureKeyPair,
        );

        $this->assertSame(VciIssuerIdentifierModeEnum::DidWeb, $identity->getMode());
        $this->assertSame(self::DID_WEB, $identity->getIssuer());
        $this->assertSame(self::DID_WEB . '#' . self::KEY_ID, $identity->getKeyId());
    }


    public function testHttpsNamesTheIssuerUrlAndTheKeySetIdentifier(): void
    {
        $identity = $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::Https),
            $this->signatureKeyPair,
        );

        $this->assertSame(VciIssuerIdentifierModeEnum::Https, $identity->getMode());
        $this->assertSame(self::ISSUER, $identity->getIssuer());
        $this->assertSame(self::KEY_ID, $identity->getKeyId());
    }


    /**
     * The did:web identifier is taken from the identifier handed in, never from configuration, so that
     * a caller identifying something the way it was created is not overruled by today's settings.
     */
    public function testTheConfiguredIdentityIsNeverReadForTheDidModes(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifier');
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerIdentifierMode');
        $this->moduleConfigMock->expects($this->never())->method('getVciIssuerDidIdentifier');

        $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB),
            $this->signatureKeyPair,
        );

        $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk),
            $this->signatureKeyPair,
        );
    }


    public function testReportsAFailureToDeriveTheDidJwk(): void
    {
        $this->didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didJwkResolverMock->method('generateDidJwkFromJwk')
            ->willThrowException(new RuntimeException('nope'));
        $this->didMock = $this->createMock(Did::class);
        $this->didMock->method('didJwkResolver')->willReturn($this->didJwkResolverMock);
        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('build')->willReturn($this->didMock);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('did:jwk');

        $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk),
            $this->signatureKeyPair,
        );
    }


    public function testReportsAFailureToMintTheDidWebVerificationMethodId(): void
    {
        $this->didDocumentFactoryMock = $this->createMock(DidDocumentFactory::class);
        $this->didDocumentFactoryMock->method('verificationMethodIdFor')
            ->willThrowException(new RuntimeException('nope'));
        $this->didMock = $this->createMock(Did::class);
        $this->didMock->method('didDocumentFactory')->willReturn($this->didDocumentFactoryMock);
        $this->didFactoryMock = $this->createMock(DidFactory::class);
        $this->didFactoryMock->method('build')->willReturn($this->didMock);

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('did:web');

        $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidWeb, self::DID_WEB),
            $this->signatureKeyPair,
        );
    }


    public function testReportsAnIssuerUrlWhichCanNotBeResolved(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willThrowException(new RuntimeException('nope'));

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('issuer URL');

        $this->sut()->resolve(
            new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::Https),
            $this->signatureKeyPair,
        );
    }
}
