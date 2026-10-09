<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use DateInterval;
use DateTimeImmutable;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Helpers as OidcHelpers;
use SimpleSAML\Module\oidc\Helpers\Random as OidcRandom;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Helpers;
use SimpleSAML\OpenID\Helpers\DateTime;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;

#[CoversClass(NonceService::class)]
#[AllowMockObjectsWithoutExpectations]
class NonceServiceTest extends TestCase
{
    protected const string ISSUER = 'https://issuer.example.com';

    protected const string KEY_ID = 'vci-1';


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


    /**
     * The parsed nonce mock made to read as a nonce of this issuer, issued at the given time and expiring five
     * minutes later, the lifetime the module configuration mock gives nonces.
     */
    protected function stubNonce(int $issuedAt): void
    {
        $this->parsedJwsMock->method('getType')->willReturn(NonceService::TYPE);
        $this->parsedJwsMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->parsedJwsMock->method('getPayloadClaim')->willReturnMap([['nonce_val', 'nonce-value']]);
        $this->parsedJwsMock->method('getIssuedAt')->willReturn($issuedAt);
        $this->parsedJwsMock->method('getExpirationTime')->willReturn($issuedAt + 300);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getVciNonceTtl')->willReturn(new DateInterval('PT5M'));
    }


    /**
     * A credential signing key pair of the kind the module configuration holds, with a real EC key.
     */
    protected function realSignatureKeyPair(): SignatureKeyPair
    {
        $key = JWKFactory::createECKey('P-256');

        return new SignatureKeyPair(
            SignatureAlgorithmEnum::ES256,
            new KeyPair(new JwkDecorator($key), new JwkDecorator($key->toPublic()), self::KEY_ID),
        );
    }


    protected function realJws(): Jws
    {
        return new Jws(new SupportedAlgorithms(new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256)));
    }


    /**
     * The service with the real JWS facade, at the real clock, signing and checking with the given key pair as
     * this issuer's only credential signing key.
     */
    protected function realSut(SignatureKeyPair $signatureKeyPair): NonceService
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $moduleConfigMock->method('getVciNonceTtl')->willReturn(new DateInterval('PT5M'));
        $moduleConfigMock->method('getActiveVciSignatureKeyPair')->willReturn($signatureKeyPair);
        $moduleConfigMock->method('getVciSignatureKeyPairBag')
            ->willReturn(new SignatureKeyPairBag($signatureKeyPair));
        $this->oidcRandomMock->method('getIdentifier')->willReturn('nonce-value');

        return new NonceService($this->realJws(), $moduleConfigMock, $this->loggerServiceMock, $this->oidcHelpersMock);
    }


    /**
     * A JWS signed with the given key pair, as this issuer signs things other than nonces with it.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $header
     */
    protected function signWith(SignatureKeyPair $signatureKeyPair, array $payload, array $header): string
    {
        return $this->realJws()->parsedJwsFactory()->fromData(
            $signatureKeyPair->getKeyPair()->getPrivateKey(),
            $signatureKeyPair->getSignatureAlgorithm(),
            $payload,
            ['kid' => self::KEY_ID] + $header,
        )->getToken();
    }


    public function testGenerateNonce(): void
    {
        $currentDateTime = new DateTimeImmutable('2024-01-01 00:00:00');
        $this->dateTimeHelperMock->method('getUtc')->willReturn($currentDateTime);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->moduleConfigMock->method('getVciNonceTtl')->willReturn(new DateInterval('PT5M'));

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
                $this->callback(fn(array $payload): bool => $payload['iat'] === $currentDateTime->getTimestamp()
                    && $payload['exp'] === $currentDateTime->getTimestamp() + 300
                    && $payload['nonce_val'] === 'mocked_random_nonce'),
                ['kid' => 'key1', 'typ' => NonceService::TYPE],
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
        $now = new DateTimeImmutable('2024-01-01 00:00:00');
        $this->dateTimeHelperMock->method('getUtc')->willReturn($now);
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->stubNonce($now->getTimestamp() - 200);

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
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->signatureKeyPairBagMock->method('getByKeyId')
            ->with('vci-retired')
            ->willReturn($this->buildSignatureKeyPair(['kty' => 'EC', 'kid' => 'vci-retired']));

        $this->parsedJwsMock->method('getKeyId')->willReturn('vci-retired');
        $this->parsedJwsMock->expects($this->once())
            ->method('verifyWithKey')
            ->with(['kty' => 'EC', 'kid' => 'vci-retired']);

        $this->stubNonce((new DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() - 200);

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
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $this->signatureKeyPairBagMock->method('getByKeyId')->with('vci-discarded')->willReturn(null);

        $this->parsedJwsMock->method('getType')->willReturn(NonceService::TYPE);
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
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getType')->willReturn(NonceService::TYPE);
        $this->parsedJwsMock->expects($this->never())->method('getPayloadClaim');
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
        $this->dateTimeHelperMock->method('getUtc')->willReturn(new DateTimeImmutable('2024-01-01 00:00:00'));
        $this->parsedJwsFactoryMock->method('fromToken')->willReturn($this->parsedJwsMock);

        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);
        $this->signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);

        $this->parsedJwsMock->method('getType')->willReturn(NonceService::TYPE);
        $this->parsedJwsMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getPayloadClaim')->willReturnMap([['nonce_val', 'nonce-value']]);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.example.com');
        $this->parsedJwsMock->method('getExpirationTime')
            ->willReturn((new DateTimeImmutable('2024-01-01 00:00:00'))->getTimestamp() - 10);
        $this->parsedJwsMock->expects($this->never())->method('getIssuedAt');
        $this->loggerServiceMock->expects($this->once())->method('warning')->with('Nonce validation failed: expired.');

        $sut = new NonceService(
            $this->jwsMock,
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        );
        $this->assertFalse($sut->validateNonce('expired_token'));
    }


    /**
     * The nonce generateNonce() signs is one validateNonce() accepts, with real keys at the real clock.
     */
    public function testValidatesANonceItIssued(): void
    {
        $sut = $this->realSut($this->realSignatureKeyPair());

        $nonce = $sut->generateNonce();

        $this->assertSame(NonceService::TYPE, $this->realJws()->parsedJwsFactory()->fromToken($nonce)->getType());
        $this->assertTrue($sut->validateNonce($nonce));
    }


    /**
     * Whatever else this issuer signs with its credential signing key, naming this issuer and unexpired, is not a
     * nonce: the first two are what a wallet can actually get hold of (a Status List Token from its public
     * endpoint), the rest a nonce with one part missing or wrong.
     *
     * @return array<string,array{0:array<string,mixed>,1:array<string,mixed>}>
     */
    public static function tokensWhichAreNotNoncesProvider(): array
    {
        $now = time();
        $nonce = ['iss' => self::ISSUER, 'iat' => $now, 'exp' => $now + 300, 'nonce_val' => 'nonce-value'];

        return [
            'a jwt_vc_json credential' => [
                ['typ' => 'JWT'],
                [
                    'iss' => self::ISSUER,
                    'sub' => 'did:jwk:holder',
                    'iat' => $now,
                    'nbf' => $now,
                    'exp' => $now + 31536000,
                    'jti' => self::ISSUER . '/vc/1',
                    'vc' => ['type' => ['VerifiableCredential']],
                ],
            ],
            'a Status List Token' => [
                ['typ' => 'statuslist+jwt'],
                [
                    'sub' => self::ISSUER . '/status-list/1',
                    'iat' => $now,
                    'exp' => $now + 86400,
                    'ttl' => 43200,
                    'iss' => self::ISSUER,
                    'status_list' => ['bits' => 1, 'lst' => 'eNrbuRgAAhcBXQ'],
                ],
            ],
            'the nonce claims without a type' => [[], $nonce],
            'the nonce claims with another type' => [['typ' => 'JWT'], $nonce],
            'the nonce type without a nonce value' => [
                ['typ' => NonceService::TYPE],
                array_diff_key($nonce, ['nonce_val' => true]),
            ],
            'the nonce type with an empty nonce value' => [
                ['typ' => NonceService::TYPE],
                ['nonce_val' => ''] + $nonce,
            ],
            'the nonce type with a nonce value which is not a string' => [
                ['typ' => NonceService::TYPE],
                ['nonce_val' => 12345] + $nonce,
            ],
            'the nonce type without an issue time' => [
                ['typ' => NonceService::TYPE],
                array_diff_key($nonce, ['iat' => true]),
            ],
            'the nonce type living a second longer than a nonce is given' => [
                ['typ' => NonceService::TYPE],
                ['exp' => $now + 301] + $nonce,
            ],
        ];
    }


    /**
     * @param array<string,mixed> $header
     * @param array<string,mixed> $payload
     */
    #[DataProvider('tokensWhichAreNotNoncesProvider')]
    public function testRefusesWhatIsNotANonceThoughSignedWithTheNonceKey(array $header, array $payload): void
    {
        $signatureKeyPair = $this->realSignatureKeyPair();

        $this->assertFalse(
            $this->realSut($signatureKeyPair)->validateNonce($this->signWith($signatureKeyPair, $payload, $header)),
        );
    }


    /**
     * The boundary of the lifetime check: a nonce given exactly the configured lifetime, as generateNonce() gives
     * every nonce, passes; the data provider has one given a second more refused.
     */
    public function testAcceptsANonceGivenExactlyTheConfiguredLifetime(): void
    {
        $signatureKeyPair = $this->realSignatureKeyPair();
        $now = time();
        $token = $this->signWith(
            $signatureKeyPair,
            ['iss' => self::ISSUER, 'iat' => $now - 10, 'exp' => $now + 290, 'nonce_val' => 'nonce-value'],
            ['typ' => NonceService::TYPE],
        );

        $this->assertTrue($this->realSut($signatureKeyPair)->validateNonce($token));
    }


    /**
     * The latest expiry is the lifetime added to the issue time in UTC, as generateNonce() adds it, whatever PHP's
     * own time zone: a day which crosses a daylight saving change there is still 86,400 seconds, and a month the
     * length of the one the nonce was issued in. The spring case is at midday: in the hour the change skips, local
     * arithmetic moves the time forward by the hour it lost and so agrees with UTC by accident.
     *
     * @return array<string,array{0:string,1:string,2:string}>
     */
    public static function permittedExpirationTimeProvider(): array
    {
        return [
            'a day across the spring change in Europe/Zagreb' => [
                'P1D',
                '2026-03-28T12:00:00Z',
                '2026-03-29T12:00:00Z',
            ],
            'a day across the autumn change in Europe/Zagreb' => [
                'P1D',
                '2026-10-24T01:30:00Z',
                '2026-10-25T01:30:00Z',
            ],
            'a month from February' => ['P1M', '2026-02-10T12:00:00Z', '2026-03-10T12:00:00Z'],
            'five minutes' => ['PT5M', '2026-10-08T12:00:00Z', '2026-10-08T12:05:00Z'],
        ];
    }


    #[DataProvider('permittedExpirationTimeProvider')]
    public function testPermitsTheLifetimeAddedToTheIssueTimeInUtc(
        string $ttl,
        string $issuedAt,
        string $expectedExpiry,
    ): void {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getVciNonceTtl')->willReturn(new DateInterval($ttl));
        $sut = new class (
            $this->jwsMock,
            $moduleConfigMock,
            $this->loggerServiceMock,
            $this->oidcHelpersMock,
        ) extends NonceService {
            public function permittedExpirationTimeOf(int $issuedAt): int
            {
                return $this->permittedExpirationTime($issuedAt);
            }
        };

        $defaultTimeZone = date_default_timezone_get();
        date_default_timezone_set('Europe/Zagreb');

        try {
            $this->assertSame(
                (new DateTimeImmutable($expectedExpiry))->getTimestamp(),
                $sut->permittedExpirationTimeOf((new DateTimeImmutable($issuedAt))->getTimestamp()),
            );
        } finally {
            date_default_timezone_set($defaultTimeZone);
        }
    }
}
