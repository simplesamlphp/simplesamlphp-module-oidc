<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use ArrayObject;
use Closure;
use DateInterval;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\OAuth2\DpopProof;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;

/**
 * The DPoP proof a request carries, checked as RFC 9449 section 4.3 has it on proofs signed by the library's
 * factory: one header field holding one JWT, the library's own checks, an algorithm the module accepts, the
 * signature, the method and URI, an `iat` within a minute of the present either way (on a pinned clock, the
 * fraction of a second included), the access token's hash, and the replay check in the protocol cache. A refusal
 * is `invalid_dpop_proof`, a 401 with the DPoP challenge at a protected resource and a 400 elsewhere; a failure of
 * the cache is the OP's own.
 */
#[CoversClass(DpopProofVerifier::class)]
#[UsesClass(VerifiedDpopProof::class)]
#[UsesClass(OidcServerException::class)]
#[AllowMockObjectsWithoutExpectations]
class DpopProofVerifierTest extends TestCase
{
    protected const int NOW = 1_700_000_000;

    protected const string RESOURCE_URL = 'https://op.example.org/module.php/oidc/credential';

    protected const string ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJhdC0xIn0.c2lnbmF0dXJl';

    protected const string CHALLENGE = 'DPoP error="invalid_dpop_proof", algs="ES256 ES384"';


    protected ModuleConfig&MockObject $moduleConfigMock;

    protected LoggerService&MockObject $loggerServiceMock;

    /** @var array<int, array{level: string, message: string, context: array}> */
    protected array $logRecords = [];

    /** @var string[] */
    protected array $acceptedAlgorithms = ['ES256', 'ES384'];

    protected bool $isCacheKeptAcrossRequests = true;

    protected float $now = self::NOW;

    /** The facade the verifier is given, with no timestamp leeway of its own. */
    protected OAuth2 $oAuth2;

    /** The facade the proofs are signed with. */
    protected OAuth2 $signer;

    protected JWK $key;

    protected ProtocolCache $protocolCache;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDpopSigningAlgorithms')
            ->willReturnCallback(fn(): array => $this->acceptedAlgorithms);
        $this->moduleConfigMock->method('isProtocolCacheKeptAcrossRequests')
            ->willReturnCallback(fn(): bool => $this->isCacheKeptAcrossRequests);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string $message, array $context = []) use ($level): void {
                    $this->logRecords[] = ['level' => $level, 'message' => $message, 'context' => $context];
                },
            );
        }

        $algorithms = new SupportedAlgorithms(
            new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256, SignatureAlgorithmEnum::ES384),
        );
        $this->oAuth2 = new OAuth2(
            supportedAlgorithms: $algorithms,
            timestampValidationLeeway: new DateInterval('PT0S'),
        );
        $this->signer = new OAuth2(supportedAlgorithms: $algorithms);
        $this->key = JWKFactory::createECKey('P-256');
        $this->protocolCache = new ProtocolCache(new Psr16Cache(new ArrayAdapter()));
    }


    protected function sut(?ProtocolCache $protocolCache = null, bool $withoutCache = false): DpopProofVerifier
    {
        return new class (
            $this->oAuth2,
            $this->moduleConfigMock,
            $withoutCache ? null : ($protocolCache ?? $this->protocolCache),
            $this->loggerServiceMock,
            fn(): float => $this->now,
        ) extends DpopProofVerifier {
            public function __construct(
                OAuth2 $oAuth2,
                ModuleConfig $moduleConfig,
                ?ProtocolCache $protocolCache,
                LoggerService $loggerService,
                private readonly Closure $clock,
            ) {
                parent::__construct($oAuth2, $moduleConfig, $protocolCache, $loggerService);
            }


            protected function currentTime(): float
            {
                return ($this->clock)();
            }
        };
    }


    /**
     * A proof the library's factory signs, for a POST to the resource with the access token, unless the claims say
     * otherwise; a claim given as null is left out.
     *
     * @param array<string,mixed> $claims
     */
    protected function proof(
        array $claims = [],
        ?JWK $key = null,
        SignatureAlgorithmEnum $algorithm = SignatureAlgorithmEnum::ES256,
    ): string {
        $payload = array_filter(
            array_merge(
                [
                    'jti' => 'proof-1',
                    'htm' => 'POST',
                    'htu' => self::RESOURCE_URL,
                    'iat' => self::NOW,
                    'ath' => DpopProof::accessTokenHash(self::ACCESS_TOKEN),
                ],
                $claims,
            ),
            fn(mixed $value): bool => $value !== null,
        );

        return $this->signer->dpopProofFactory()
            ->fromData(new JwkDecorator($key ?? $this->key), $algorithm, $payload)
            ->getToken();
    }


    /**
     * A JWS signed with the proof key as given, which the library's factory would not sign: for proofs which fail
     * the checks the library makes when it parses one.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $header
     */
    protected function rawProof(array $payload, array $header): string
    {
        return $this->signer->jwsSerializerManagerDecorator()->serialize(
            JwsSerializerEnum::Compact->value,
            $this->signer->jwsDecoratorBuilder()->fromData(
                new JwkDecorator($this->key),
                SignatureAlgorithmEnum::ES256,
                $payload,
                $header,
            ),
        );
    }


    protected function request(?string $proof, string $method = 'POST'): ServerRequestInterface
    {
        $request = new ServerRequest($method, self::RESOURCE_URL);

        return $proof === null ? $request : $request->withHeader('DPoP', $proof);
    }


    protected function refusalOf(
        ServerRequestInterface $request,
        ?string $accessToken = self::ACCESS_TOKEN,
        ?DpopProofVerifier $sut = null,
    ): OidcServerException {
        try {
            ($sut ?? $this->sut())->verify($request, self::RESOURCE_URL, $accessToken);
        } catch (OidcServerException $exception) {
            return $exception;
        }

        $this->fail('The proof must be refused.');
    }


    /**
     * At a protected resource: a 401 with the DPoP challenge naming the error and the algorithms (RFC 9449 section
     * 7.1), with the check which failed in the hint.
     */
    protected function assertRefusedAtTheResource(OidcServerException $exception, string $hint): void
    {
        $this->assertSame('invalid_dpop_proof', $exception->getErrorType());
        $this->assertSame(401, $exception->getHttpStatusCode());
        $this->assertSame(self::CHALLENGE, $exception->getWwwAuthenticate());
        $this->assertStringContainsString($hint, (string)$exception->getHint());
    }


    protected function assertAnsweredAsAServerError(OidcServerException $exception): void
    {
        $this->assertSame('server_error', $exception->getErrorType());
        $this->assertSame(500, $exception->getHttpStatusCode());
        $this->assertNull($exception->getWwwAuthenticate());
    }


    /**
     * The thumbprint RFC 7638 has for the public key, computed by the JOSE library rather than by the code under
     * test.
     */
    protected function thumbprintOf(JWK $key): string
    {
        return $key->toPublic()->thumbprint('sha256');
    }


    public function testAnswersNullForARequestWithoutAProof(): void
    {
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->never())->method('set');

        $this->assertNull(
            $this->sut($protocolCacheMock)->verify($this->request(null), self::RESOURCE_URL, self::ACCESS_TOKEN),
        );
    }


    public function testAcceptsAProofForTheRequestAndTheAccessToken(): void
    {
        $verified = $this->sut()->verify($this->request($this->proof()), self::RESOURCE_URL, self::ACCESS_TOKEN);

        $this->assertInstanceOf(VerifiedDpopProof::class, $verified);
        $this->assertSame($this->thumbprintOf($this->key), $verified->getJwkThumbprint());
        $this->assertSame('proof-1', $verified->getProof()->getJwtId());
    }


    /**
     * At the token endpoint there is no access token, so the proof carries no `ath`, and a refusal is section 5's
     * 400, with no challenge.
     */
    public function testChecksAProofWithoutAnAccessTokenAsTheTokenEndpointDoes(): void
    {
        $verified = $this->sut()->verify(
            $this->request($this->proof(['ath' => null])),
            self::RESOURCE_URL,
            null,
        );
        $this->assertSame($this->thumbprintOf($this->key), $verified?->getJwkThumbprint());

        $exception = $this->refusalOf($this->request($this->proof(['jti' => 'proof-2', 'htm' => 'GET'])), null);

        $this->assertSame('invalid_dpop_proof', $exception->getErrorType());
        $this->assertSame(400, $exception->getHttpStatusCode());
        $this->assertNull($exception->getWwwAuthenticate());
    }


    /**
     * Section 4.3 check 1: not more than one DPoP header field.
     */
    public function testRefusesMoreThanOneProofHeaderField(): void
    {
        $request = $this->request($this->proof())->withAddedHeader('DPoP', $this->proof(['jti' => 'proof-2']));

        $this->assertRefusedAtTheResource($this->refusalOf($request), 'more than one DPoP header field');
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function valueWhichIsNotOneJwtProvider(): array
    {
        return [
            'two values folded into one field' => ['%1$s, %1$s'],
            'a blank inside' => ['%1$s %1$s'],
            'empty' => [''],
            'characters outside token68' => ['{"typ":"dpop+jwt"}'],
        ];
    }


    /**
     * Section 4.3 check 2: the field value is a single JWT. A server joins repeated header fields into one value
     * with commas, so a comma is two proofs.
     */
    #[DataProvider('valueWhichIsNotOneJwtProvider')]
    public function testRefusesAFieldValueWhichIsNotOneJwt(string $format): void
    {
        $request = $this->request(sprintf($format, $this->proof()));

        $this->assertRefusedAtTheResource($this->refusalOf($request), 'does not hold one JWT');
    }


    public function testReadsAProofWithBlanksAroundIt(): void
    {
        $verified = $this->sut()->verify(
            $this->request(" \t" . $this->proof() . "\t "),
            self::RESOURCE_URL,
            self::ACCESS_TOKEN,
        );

        $this->assertInstanceOf(VerifiedDpopProof::class, $verified);
    }


    /**
     * @return array<string, array{0: array<string,mixed>, 1: array<string,mixed>}>
     */
    public static function proofTheLibraryRefusesProvider(): array
    {
        $payload = [
            'jti' => 'proof-1',
            'htm' => 'POST',
            'htu' => self::RESOURCE_URL,
            'iat' => self::NOW,
        ];

        return [
            'no jti' => [array_diff_key($payload, ['jti' => true]), []],
            'no htu' => [array_diff_key($payload, ['htu' => true]), []],
            'iat a numeric string' => [['iat' => (string)self::NOW] + $payload, []],
            'typ JWT' => [$payload, ['typ' => 'JWT']],
            'no jwk' => [$payload, ['jwk' => null]],
            'a private key in jwk' => [$payload, ['jwk' => 'private']],
        ];
    }


    /**
     * Whatever the library refuses when it parses the proof is the proof's fault: `invalid_dpop_proof` with a
     * description of the verifier's own, never a 500, and the library's message, which may quote what the proof
     * carried, goes to the debug log only.
     *
     * @param array<string,mixed> $payload
     * @param array<string,mixed> $headerOverrides
     */
    #[DataProvider('proofTheLibraryRefusesProvider')]
    public function testRefusesAProofTheLibraryRefuses(array $payload, array $headerOverrides): void
    {
        $header = array_merge(
            ['typ' => 'dpop+jwt', 'jwk' => $this->key->toPublic()->all()],
            $headerOverrides,
        );
        if (($header['jwk'] ?? null) === 'private') {
            $header['jwk'] = $this->key->all();
        }
        $header = array_filter($header, fn(mixed $value): bool => $value !== null);

        $exception = $this->refusalOf($this->request($this->rawProof($payload, $header)));

        $this->assertRefusedAtTheResource($exception, 'fails a check of RFC 9449 section 4.3');
        $this->assertNull($exception->getPrevious());
        $this->assertSame('debug', $this->logRecords[0]['level'] ?? null);
        $this->assertStringStartsWith('DPoP proof refused: ', $this->logRecords[0]['message']);
    }


    /**
     * Section 4.3 check 5's local policy: an algorithm the library knows is still refused when the module does not
     * accept it.
     */
    public function testRefusesAnAlgorithmTheModuleDoesNotAccept(): void
    {
        $this->acceptedAlgorithms = ['ES256'];
        $key = JWKFactory::createECKey('P-384');

        $exception = $this->refusalOf($this->request($this->proof([], $key, SignatureAlgorithmEnum::ES384)));

        $this->assertSame('invalid_dpop_proof', $exception->getErrorType());
        $this->assertStringContainsString('algorithm which is not accepted', (string)$exception->getHint());
        $this->assertSame('DPoP error="invalid_dpop_proof", algs="ES256"', $exception->getWwwAuthenticate());
    }


    public function testAcceptsAnotherAlgorithmTheModuleAccepts(): void
    {
        $key = JWKFactory::createECKey('P-384');

        $verified = $this->sut()->verify(
            $this->request($this->proof([], $key, SignatureAlgorithmEnum::ES384)),
            self::RESOURCE_URL,
            self::ACCESS_TOKEN,
        );

        $this->assertSame($this->thumbprintOf($key), $verified?->getJwkThumbprint());
    }


    /**
     * Section 4.3 check 6: the header names one key and the signature is another's.
     */
    public function testRefusesAProofWhoseSignatureIsNotByItsKey(): void
    {
        [$header, $payload] = explode('.', $this->proof());
        $otherSignature = explode('.', $this->proof([], JWKFactory::createECKey('P-256')))[2];

        $exception = $this->refusalOf($this->request($header . '.' . $payload . '.' . $otherSignature));

        $this->assertRefusedAtTheResource($exception, 'signature does not verify');
    }


    /**
     * @return array<string, array{0: array<string,mixed>, 1: string}>
     */
    public static function proofForAnotherRequestProvider(): array
    {
        return [
            'another method' => [['htm' => 'GET'], 'POST'],
            'the method in lower case' => [['htm' => 'post'], 'POST'],
            'another endpoint' => [['htu' => 'https://op.example.org/module.php/oidc/userinfo'], 'POST'],
            'another host' => [['htu' => 'https://other.example.org/module.php/oidc/credential'], 'POST'],
            'another scheme' => [['htu' => 'http://op.example.org/module.php/oidc/credential'], 'POST'],
            'a POST proof sent with a GET' => [[], 'GET'],
        ];
    }


    /**
     * Section 4.3 checks 8 and 9: the method exactly, and the URI against the one this OP publishes.
     *
     * @param array<string,mixed> $claims
     */
    #[DataProvider('proofForAnotherRequestProvider')]
    public function testRefusesAProofForAnotherRequest(array $claims, string $method): void
    {
        $exception = $this->refusalOf($this->request($this->proof($claims), $method));

        $this->assertRefusedAtTheResource($exception, 'not for this request');
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function equivalentTargetUriProvider(): array
    {
        return [
            'a query' => [self::RESOURCE_URL . '?a=b'],
            'a fragment' => [self::RESOURCE_URL . '#f'],
            'the scheme and host in upper case' => ['HTTPS://OP.EXAMPLE.ORG/module.php/oidc/credential'],
            'the default port' => ['https://op.example.org:443/module.php/oidc/credential'],
            'a dot segment' => ['https://op.example.org/module.php/x/../oidc/credential'],
        ];
    }


    /**
     * Section 4.3 check 9 ignores the query and the fragment, and normalizes as RFC 3986 sections 6.2.2 and 6.2.3
     * have it.
     */
    #[DataProvider('equivalentTargetUriProvider')]
    public function testAcceptsATargetUriWhichNormalizesToTheResource(string $htu): void
    {
        $verified = $this->sut()->verify(
            $this->request($this->proof(['htu' => $htu])),
            self::RESOURCE_URL,
            self::ACCESS_TOKEN,
        );

        $this->assertInstanceOf(VerifiedDpopProof::class, $verified);
    }


    /**
     * The URI is the published one, whatever the request says it was sent to.
     */
    public function testComparesTheTargetUriWithThePublishedUrlNotTheRequestOne(): void
    {
        $request = (new ServerRequest('POST', 'https://alias.example.net/credential'))
            ->withHeader('DPoP', $this->proof());

        $verified = $this->sut()->verify($request, self::RESOURCE_URL, self::ACCESS_TOKEN);

        $this->assertInstanceOf(VerifiedDpopProof::class, $verified);

        $aliased = (new ServerRequest('POST', self::RESOURCE_URL))
            ->withHeader('DPoP', $this->proof(['jti' => 'proof-2', 'htu' => 'https://alias.example.net/credential']));

        $this->assertRefusedAtTheResource($this->refusalOf($aliased), 'not for this request');
    }


    /**
     * @return array<string, array{0: float|int, 1: bool}>
     */
    public static function issuedAtProvider(): array
    {
        return [
            'now' => [self::NOW, true],
            'a minute ago' => [self::NOW - 60, true],
            'a minute ahead' => [self::NOW + 60, true],
            'a minute and a second ago' => [self::NOW - 61, false],
            'a minute and a second ahead' => [self::NOW + 61, false],
            // Compared with its fraction: truncated, these would pass.
            'a minute and half a second ago' => [self::NOW - 60.5, false],
            'a minute and half a second ahead' => [self::NOW + 60.5, false],
            'an hour ago' => [self::NOW - 3600, false],
            'an hour ahead' => [self::NOW + 3600, false],
        ];
    }


    /**
     * Section 4.3 check 11: within PROOF_WINDOW_SECONDS of the present either way, both ends included, on a
     * pinned clock.
     */
    #[DataProvider('issuedAtProvider')]
    public function testHoldsTheIssuedAtToAMinuteEitherWay(float|int $issuedAt, bool $isAccepted): void
    {
        $request = $this->request($this->proof(['iat' => $issuedAt]));

        if ($isAccepted) {
            $this->assertInstanceOf(
                VerifiedDpopProof::class,
                $this->sut()->verify($request, self::RESOURCE_URL, self::ACCESS_TOKEN),
            );
            return;
        }

        $this->assertRefusedAtTheResource($this->refusalOf($request), 'not created within the accepted time window');
    }


    /**
     * The present carries a fraction too: half a second past the end of the window is past it.
     */
    public function testHoldsTheWindowAgainstTheFractionOfTheClock(): void
    {
        $this->now = self::NOW + 60.5;

        $this->assertRefusedAtTheResource(
            $this->refusalOf($this->request($this->proof())),
            'not created within the accepted time window',
        );
    }


    /**
     * The verifier's own clock keeps the fraction of a second, so that an `iat` half a second outside the window
     * is outside it. The clock reads a whole second once in a million readings, so three do.
     */
    public function testTheClockKeepsTheFractionOfASecond(): void
    {
        $sut = new class (
            $this->oAuth2,
            $this->moduleConfigMock,
            null,
            $this->loggerServiceMock,
        ) extends DpopProofVerifier {
            public function now(): float
            {
                return $this->currentTime();
            }
        };

        $readings = [$sut->now(), $sut->now(), $sut->now()];

        $this->assertEqualsWithDelta(microtime(true), $readings[2], 1.0);
        $this->assertNotSame(
            [],
            array_filter($readings, fn(float $reading): bool => $reading !== floor($reading)),
        );
    }


    /**
     * The library's own checks of `iat` get the verifier's minute as their leeway, not the module's (here none):
     * a proof made thirty seconds ahead of the real clock passes them.
     */
    public function testGivesTheLibraryItsOwnLeeway(): void
    {
        $this->now = (float)time();

        $verified = $this->sut()->verify(
            $this->request($this->proof(['iat' => time() + 30])),
            self::RESOURCE_URL,
            self::ACCESS_TOKEN,
        );

        $this->assertInstanceOf(VerifiedDpopProof::class, $verified);
    }


    /**
     * @return array<string, array{0: array<string,mixed>}>
     */
    public static function proofWithoutTheAccessTokenHashProvider(): array
    {
        return [
            'no ath' => [['ath' => null]],
            'the hash of another token' => [['ath' => DpopProof::accessTokenHash('another-token')]],
        ];
    }


    /**
     * The first half of section 4.3 check 12: with an access token, the proof carries its hash.
     *
     * @param array<string,mixed> $claims
     */
    #[DataProvider('proofWithoutTheAccessTokenHashProvider')]
    public function testRefusesAProofWithoutTheAccessTokenHash(array $claims): void
    {
        $exception = $this->refusalOf($this->request($this->proof($claims)));

        $this->assertRefusedAtTheResource($exception, 'hash of the access token');
    }


    /**
     * Section 11.1: a proof is accepted once.
     */
    public function testRefusesAProofUsedBefore(): void
    {
        $sut = $this->sut();
        $proof = $this->proof();

        $this->assertInstanceOf(
            VerifiedDpopProof::class,
            $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN),
        );

        $this->assertRefusedAtTheResource($this->refusalOf($this->request($proof), sut: $sut), 'used before');
    }


    /**
     * The `jti` is remembered in the context of the key and the endpoint: another key's proof, or a proof for
     * another endpoint, with the same `jti` is a proof of its own.
     */
    public function testRemembersTheIdentifierForTheKeyAndTheEndpoint(): void
    {
        $sut = $this->sut();
        $sut->verify($this->request($this->proof()), self::RESOURCE_URL, self::ACCESS_TOKEN);

        $otherKey = JWKFactory::createECKey('P-256');
        $this->assertInstanceOf(
            VerifiedDpopProof::class,
            $sut->verify($this->request($this->proof([], $otherKey)), self::RESOURCE_URL, self::ACCESS_TOKEN),
        );

        $userInfoUrl = 'https://op.example.org/module.php/oidc/userinfo';
        $this->assertInstanceOf(
            VerifiedDpopProof::class,
            $sut->verify(
                (new ServerRequest('POST', $userInfoUrl))->withHeader('DPoP', $this->proof(['htu' => $userInfoUrl])),
                $userInfoUrl,
                self::ACCESS_TOKEN,
            ),
        );
    }


    /**
     * The record is written for REPLAY_TTL_SECONDS under a key which holds neither the `jti` nor the key, and
     * only for a proof which passed every other check.
     */
    public function testRemembersAProofForTheAcceptanceWindowUnderAHashedKey(): void
    {
        $writes = [];
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willReturnCallback(
            function (string ...$keyElements) use (&$writes): bool {
                return isset($writes[implode('|', $keyElements)]);
            },
        );
        $protocolCacheMock->method('set')->willReturnCallback(
            function (mixed $value, int $ttl, string ...$keyElements) use (&$writes): bool {
                $writes[implode('|', $keyElements)] = $ttl;

                return true;
            },
        );

        $sut = $this->sut($protocolCacheMock);
        $this->refusalOf($this->request($this->proof(['htm' => 'GET'])), sut: $sut);
        $this->assertSame([], $writes);

        $sut->verify(
            $this->request($this->proof(['jti' => 'proof-identifier'])),
            self::RESOURCE_URL,
            self::ACCESS_TOKEN,
        );

        // The 120 seconds a proof is accepted for, both ends included, and a margin.
        $this->assertSame([125], array_values($writes));
        $key = (string)array_key_first($writes);
        $this->assertStringStartsWith('dpop_jti|', $key);
        $this->assertStringNotContainsString('proof-identifier', $key);
        $this->assertStringNotContainsString($this->thumbprintOf($this->key), $key);
    }


    public function testChecksNoReplayWithoutAProtocolCache(): void
    {
        $sut = $this->sut(withoutCache: true);
        $proof = $this->proof();

        $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN);

        $this->assertInstanceOf(
            VerifiedDpopProof::class,
            $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN),
        );
    }


    /**
     * A cache which keeps nothing from one request to the next counts as none: nothing is written to it.
     */
    public function testChecksNoReplayWithACacheWhichKeepsNothingAcrossRequests(): void
    {
        $this->isCacheKeptAcrossRequests = false;
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->expects($this->never())->method('set');
        $protocolCacheMock->expects($this->never())->method('has');
        $sut = $this->sut($protocolCacheMock);
        $proof = $this->proof();

        $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN);

        $this->assertInstanceOf(
            VerifiedDpopProof::class,
            $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN),
        );
    }


    /**
     * A Symfony cache whose backend can be made to fail as Symfony's adapters do, which log the failure rather
     * than throw: a failed write is reported as not done, a lost one is reported as done and kept nowhere, and a
     * failed read is a miss.
     *
     * @param \ArrayObject<string,bool> $fail Its 'writes', 'keeps' and 'reads' switches.
     */
    protected function flakyCache(ArrayObject $fail): ProtocolCache
    {
        return new ProtocolCache(new Psr16Cache(new class ($fail) extends ArrayAdapter {
            /** @param \ArrayObject<string,bool> $fail */
            public function __construct(private readonly ArrayObject $fail)
            {
                parent::__construct();
            }


            public function save(CacheItemInterface $item): bool
            {
                if ($this->fail['writes']) {
                    return false;
                }

                return $this->fail['keeps'] ? true : parent::save($item);
            }


            public function hasItem(mixed $key): bool
            {
                return !$this->fail['reads'] && parent::hasItem($key);
            }
        }));
    }


    /**
     * @return array<string, array{0: string}>
     */
    public static function cacheWhichDoesNotKeepTheRecordProvider(): array
    {
        return [
            'the write reported as not done' => ['writes'],
            'the write reported as done and lost' => ['keeps'],
        ];
    }


    /**
     * A record the cache does not keep fails the request as the OP's own failure: accepted, the proof could be
     * replayed.
     */
    #[DataProvider('cacheWhichDoesNotKeepTheRecordProvider')]
    public function testAnswersACacheWhichDoesNotKeepTheRecordAsTheServersOwnFailure(string $failure): void
    {
        $fail = new ArrayObject(['writes' => false, 'keeps' => false, 'reads' => false]);
        $fail[$failure] = true;

        $this->assertAnsweredAsAServerError(
            $this->refusalOf($this->request($this->proof()), sut: $this->sut($this->flakyCache($fail))),
        );
    }


    /**
     * A read which fails is a miss, so a proof whose record can not be read is taken for one not seen: the gap the
     * class docblock owns up to. The read back after the write fails the same way, so the request fails too.
     */
    public function testAnswersACacheWhichReportsTheWriteAsNotDoneAsTheServersOwnFailureEvenIfItReadsBack(): void
    {
        // A chain of adapters reports a write one of its layers lost, which a read answered from another would
        // not show.
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willReturnOnConsecutiveCalls(false, true);
        $protocolCacheMock->method('set')->willReturn(false);

        $this->assertAnsweredAsAServerError(
            $this->refusalOf($this->request($this->proof()), sut: $this->sut($protocolCacheMock)),
        );
    }


    public function testAnswersAnUnreadableCacheAsTheServersOwnFailure(): void
    {
        $fail = new ArrayObject(['writes' => false, 'keeps' => false, 'reads' => true]);

        $this->assertAnsweredAsAServerError(
            $this->refusalOf($this->request($this->proof()), sut: $this->sut($this->flakyCache($fail))),
        );
    }


    public function testAnswersACacheWhichThrowsAsTheServersOwnFailure(): void
    {
        $failure = new RuntimeException('Cache backend down.');
        $protocolCacheMock = $this->createMock(ProtocolCache::class);
        $protocolCacheMock->method('has')->willThrowException($failure);

        $exception = $this->refusalOf($this->request($this->proof()), sut: $this->sut($protocolCacheMock));

        $this->assertAnsweredAsAServerError($exception);
        $this->assertSame($failure, $exception->getPrevious());
    }


    /**
     * A published URL which is no URL a proof could name is a fault of the configuration, not of the proof.
     */
    public function testAnswersAnUnusableEndpointUrlAsTheServersOwnFailure(): void
    {
        try {
            $this->sut()->verify($this->request($this->proof()), 'not a url', self::ACCESS_TOKEN);
            $this->fail('The request must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertAnsweredAsAServerError($exception);
        }
    }


    /**
     * Neither the proof, nor its `jti`, nor the access token is logged, whatever the outcome; the thumbprint may
     * be, at debug.
     */
    public function testLogsNeitherTheProofNorItsIdentifierNorTheAccessToken(): void
    {
        $sut = $this->sut();
        $proof = $this->proof(['jti' => 'secret-proof-identifier']);
        $sut->verify($this->request($proof), self::RESOURCE_URL, self::ACCESS_TOKEN);
        $this->refusalOf($this->request($proof), sut: $sut);
        $this->refusalOf($this->request($this->proof(['jti' => 'secret-proof-identifier', 'htm' => 'GET'])));

        $logged = json_encode($this->logRecords, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $this->assertNotSame('[]', $logged);
        foreach (
            [
                $proof,
                explode('.', $proof)[1],
                'secret-proof-identifier',
                self::ACCESS_TOKEN,
                DpopProof::accessTokenHash(self::ACCESS_TOKEN),
            ] as $secret
        ) {
            $this->assertStringNotContainsString($secret, $logged);
        }

        foreach ($this->logRecords as $logRecord) {
            $this->assertSame('debug', $logRecord['level']);
        }
    }
}
