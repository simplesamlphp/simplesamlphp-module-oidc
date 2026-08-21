<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers as OidcHelpers;
use SimpleSAML\Module\oidc\Helpers\Random as OidcRandom;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\DateTime;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(NonceService::class)]
class NonceServiceTest extends TestCase
{
    protected MockObject $jwsMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $parsedJwsFactoryMock;
    protected MockObject $parsedJwsMock;
    protected MockObject $signatureKeyPairBagMock;
    protected MockObject $signatureKeyPairMock;
    protected MockObject $helpersMock;
    protected MockObject $dateTimeHelperMock;
    protected MockObject $oidcHelpersMock;
    protected MockObject $oidcRandomMock;

    public function setUp(): void
    {
        $this->jwsMock = $this->createMock(Jws::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->parsedJwsFactoryMock = $this->createMock(ParsedJwsFactory::class);
        $this->parsedJwsMock = $this->createMock(ParsedJws::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);
        $this->oidcHelpersMock = $this->createMock(OidcHelpers::class);
        $this->oidcRandomMock = $this->createMock(OidcRandom::class);

        $this->jwsMock->method('parsedJwsFactory')->willReturn($this->parsedJwsFactoryMock);
        $this->jwsMock->method('helpers')->willReturn($this->helpersMock);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);
        $this->oidcHelpersMock->method('random')->willReturn($this->oidcRandomMock);

        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')->willReturn($this->signatureKeyPairMock);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')->willReturn($this->signatureKeyPairBagMock);
    }

    /**
     * A key pair whose public key is the given JWK, so a test can tell which key a nonce was checked
     * against.
     *
     * @param array<string,mixed> $publicJwk
     */
    protected function buildSignatureKeyPair(array $publicJwk): MockObject
    {
        $publicKey = (new JwkDecoratorFactory())->fromData($publicJwk);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        return $signatureKeyPairMock;
    }

    public function testGenerateNonce(): void
    {
        $currentDateTime = new \DateTimeImmutable('2024-01-01 00:00:00');
        $this->dateTimeHelperMock->method('getUtc')->willReturn($currentDateTime);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getVciNonceTtl')->willReturn(new \DateInterval('PT5M'));

        $privateKeyMock = $this->createMock(JwkDecorator::class);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPrivateKey')->willReturn($privateKeyMock);
        $keyPairMock->method('getKeyId')->willReturn('key1');
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);

        $this->oidcRandomMock->expects($this->once())
            ->method('getIdentifier')
            ->with(16)
            ->willReturn('mocked_random_nonce');

        $this->parsedJwsFactoryMock->expects($this->once())
            ->method('fromData')
            ->with(
                $this->anything(),
                $this->anything(),
                $this->callback(function (array $payload) use ($currentDateTime): bool {
                    return $payload['iat'] === $currentDateTime->getTimestamp()
                        && $payload['exp'] === $currentDateTime->getTimestamp() + 300
                        && $payload['nonce_val'] === 'mocked_random_nonce';
                }),
                $this->anything(),
            )
            ->willReturn($this->parsedJwsMock);

        $this->parsedJwsMock->method('getToken')->willReturn('mocked_token');

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $nonce = $sut->generateNonce();

        $this->assertEquals('mocked_token', $nonce);
    }

    public function testValidateNonceSuccess(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new \DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() + 100);

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertTrue($sut->validateNonce('valid_token'));
    }

    /**
     * A nonce handed out shortly before a key rollover is still this issuer's nonce. It names the key
     * it was signed with, so it is checked against that key rather than against whichever key has since
     * taken over signing. Rejecting it would read, to the wallet holding it, as its proof of possession
     * being refused for the remainder of the nonce's lifetime.
     */
    public function testValidatesANonceSignedByAKeyWhichNoLongerSigns(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->signatureKeyPairBagMock->method('getByKeyId')
            ->with('vci-retired')
            ->willReturn($this->buildSignatureKeyPair(['kty' => 'EC', 'kid' => 'vci-retired']));

        $this->parsedJwsMock->method('getKeyId')->willReturn('vci-retired');
        $this->parsedJwsMock->expects($this->once())
            ->method('verifyWithKey')
            ->with(['kty' => 'EC', 'kid' => 'vci-retired']);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new \DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() + 100);

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertTrue($sut->validateNonce('nonce_from_previous_key'));
    }

    /**
     * Naming a key is not the same as being able to sign with it, but a key this deployment does not
     * hold can not be checked against at all, so the nonce is refused rather than checked against some
     * other key which would happen to be available.
     */
    public function testRejectsANonceNamingAKeyWhichIsNotConfigured(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->signatureKeyPairBagMock->method('getByKeyId')->with('vci-discarded')->willReturn(null);

        $this->parsedJwsMock->method('getKeyId')->willReturn('vci-discarded');
        $this->parsedJwsMock->expects($this->never())->method('verifyWithKey');
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with($this->stringContains('vci-discarded'));

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertFalse($sut->validateNonce('nonce_from_discarded_key'));
    }

    public function testValidateNonceInvalidIssuer(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://other.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertFalse($sut->validateNonce('invalid_issuer_token'));
    }

    public function testValidateNonceExpired(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new \DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() - 10);

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertFalse($sut->validateNonce('expired_token'));
    }
}
