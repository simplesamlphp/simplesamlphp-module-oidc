<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Jose\Component\Core\JWK;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\DateTime;
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

    public function setUp(): void
    {
        $this->jwsMock = $this->createMock(Jws::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->parsedJwsFactoryMock = $this->createMock(ParsedJwsFactory::class);
        $this->parsedJwsMock = $this->createMock(ParsedJws::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->dateTimeHelperMock = $this->createMock(DateTime::class);

        $this->jwsMock->method('parsedJwsFactory')->willReturn($this->parsedJwsFactoryMock);
        $this->jwsMock->method('helpers')->willReturn($this->helpersMock);
        $this->helpersMock->method('dateTime')->willReturn($this->dateTimeHelperMock);

        $this->signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $this->signatureKeyPairBagMock->method('getFirstOrFail')->willReturn($this->signatureKeyPairMock);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')->willReturn($this->signatureKeyPairBagMock);
    }

    public function testGenerateNonce(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');

        $privateKeyMock = $this->createMock(JwkDecorator::class);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPrivateKey')->willReturn($privateKeyMock);
        $keyPairMock->method('getKeyId')->willReturn('key1');
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $this->signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);

        $this->parsedJwsFactoryMock->expects($this->once())
            ->method('fromData')
            ->willReturn($this->parsedJwsMock);

        $this->parsedJwsMock->method('getToken')->willReturn('mocked_token');

        $sut = new NonceService($this->jwsMock, $this->moduleConfigMock, $this->loggerServiceMock);
        $nonce = $sut->generateNonce();

        $this->assertEquals('mocked_token', $nonce);
    }

    public function testValidateNonceSuccess(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $jwkMock = $this->createMock(JWK::class);
        $jwkMock->method('all')->willReturn(['kty' => 'EC']);
        $publicKeyMock = $this->createMock(JwkDecorator::class);
        $publicKeyMock->method('jwk')->willReturn($jwkMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKeyMock);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new \DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() + 100);

        $sut = new NonceService($this->jwsMock, $this->moduleConfigMock, $this->loggerServiceMock);
        $this->assertTrue($sut->validateNonce('valid_token'));
    }

    public function testValidateNonceInvalidIssuer(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $jwkMock = $this->createMock(JWK::class);
        $jwkMock->method('all')->willReturn(['kty' => 'EC']);
        $publicKeyMock = $this->createMock(JwkDecorator::class);
        $publicKeyMock->method('jwk')->willReturn($jwkMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKeyMock);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://other.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');

        $sut = new NonceService($this->jwsMock, $this->moduleConfigMock, $this->loggerServiceMock);
        $this->assertFalse($sut->validateNonce('invalid_issuer_token'));
    }

    public function testValidateNonceExpired(): void
    {
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new \DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $jwkMock = $this->createMock(JWK::class);
        $jwkMock->method('all')->willReturn(['kty' => 'EC']);
        $publicKeyMock = $this->createMock(JwkDecorator::class);
        $publicKeyMock->method('jwk')->willReturn($jwkMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKeyMock);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new \DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() - 10);

        $sut = new NonceService($this->jwsMock, $this->moduleConfigMock, $this->loggerServiceMock);
        $this->assertFalse($sut->validateNonce('expired_token'));
    }
}
