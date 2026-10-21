<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use Closure;
use DateInterval;
use Jose\Component\KeyManagement\JWKFactory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Validators\ClientAttestationVerifier;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\ValueAbstracts\ClientAttestationTrust;
use SimpleSAML\Module\oidc\ValueAbstracts\PresentedClientAttestation;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\OAuth2;
use SimpleSAML\OpenID\X509;
use SimpleSAML\OpenID\X509\CertificateChain;
use SimpleSAML\OpenID\X509\CertificatePathValidator;
use SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\CertificateBuilder;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;

/**
 * The Client Attestation and PoP a request carries, checked as draft-ietf-oauth-attestation-based-client-auth-07
 * section 9 has it, on attestations signed by a wallet provider's certificate under a PKI made when the tests run:
 * one field of each holding one JWT, the library's own checks, the algorithms, the client's registration and trust,
 * the attester and its certificate path (the trust anchors, the pinned issuing CA, the pinned identity), the
 * signatures, the audience, the time checks on a clock read after the path validation, and the replay check in the
 * protocol cache. A refusal is an AuthorizationException; a failure of the cache is the OP's own.
 */
#[CoversClass(ClientAttestationVerifier::class)]
#[UsesClass(PresentedClientAttestation::class)]
#[UsesClass(ClientAttestationTrust::class)]
#[UsesClass(ClientEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientAttestationVerifierTest extends TestCase
{
    protected const string TOKEN_URL = 'https://op.example.org/module.php/oidc/token';


    protected ClientAttestationBuilder $builder;

    protected ModuleConfig&MockObject $moduleConfigMock;

    protected LoggerService&MockObject $loggerServiceMock;

    /** @var array<int, array{level: string, message: string, context: array}> */
    protected array $logRecords = [];

    /** @var string[] */
    protected array $acceptedAlgorithms = ['ES256', 'ES384'];

    protected bool $isCacheKeptAcrossRequests = true;

    protected string $leeway = 'PT1M';

    /** The present as the verifier sees it; null for the real clock. */
    protected ?float $now = null;

    /** The present once the certificate path has been validated, when it is to differ from $now. */
    protected ?float $nowAfterPathValidation = null;

    protected bool $hasValidatedPath = false;

    protected ProtocolCache $protocolCache;


    protected function setUp(): void
    {
        $this->builder = new ClientAttestationBuilder();

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getClientAttestationSigningAlgorithms')
            ->willReturnCallback(fn(): array => $this->acceptedAlgorithms);
        $this->moduleConfigMock->method('isProtocolCacheKeptAcrossRequests')
            ->willReturnCallback(fn(): bool => $this->isCacheKeptAcrossRequests);
        $this->moduleConfigMock->method('getTimestampValidationLeeway')
            ->willReturnCallback(fn(): DateInterval => new DateInterval($this->leeway));
        $this->moduleConfigMock->method('getIssuer')->willReturn(ClientAttestationBuilder::ISSUER);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        foreach (['debug', 'info', 'notice', 'warning', 'error'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string $message, array $context = []) use ($level): void {
                    $this->logRecords[] = ['level' => $level, 'message' => $message, 'context' => $context];
                },
            );
        }

        $this->protocolCache = new ProtocolCache(new Psr16Cache(new ArrayAdapter()));
    }


    protected function sut(
        ?ProtocolCache $protocolCache = null,
        bool $withoutCache = false,
        ?string $temporaryDirectory = null,
    ): ClientAttestationVerifier {
        // A path validator which notes that it ran, so that the clock can tell before from after.
        $x509 = new class (fn() => $this->hasValidatedPath = true, $temporaryDirectory) extends X509 {
            public function __construct(private readonly Closure $onValidated, ?string $temporaryDirectory)
            {
                parent::__construct($temporaryDirectory);
            }


            public function certificatePathValidator(): CertificatePathValidator
            {
                $onValidated = $this->onValidated;

                return $this->certificatePathValidator ??= new class (
                    $onValidated,
                    $this->temporaryDirectory,
                ) extends CertificatePathValidator {
                    public function __construct(private readonly Closure $onValidated, ?string $temporaryDirectory)
                    {
                        parent::__construct($temporaryDirectory);
                    }


                    public function validate(CertificateChain $chain, array $trustAnchors): CertificateChain
                    {
                        $validatedPath = parent::validate($chain, $trustAnchors);
                        ($this->onValidated)();

                        return $validatedPath;
                    }
                };
            }
        };

        $clock = function (): float {
            if ($this->hasValidatedPath && $this->nowAfterPathValidation !== null) {
                return $this->nowAfterPathValidation;
            }

            return $this->now ?? microtime(true);
        };

        return new class (
            new OAuth2(supportedAlgorithms: ClientAttestationBuilder::supportedAlgorithms()),
            $x509,
            $this->moduleConfigMock,
            $withoutCache ? null : ($protocolCache ?? $this->protocolCache),
            $this->loggerServiceMock,
            $clock,
        ) extends ClientAttestationVerifier {
            public function __construct(
                OAuth2 $oAuth2,
                X509 $x509,
                ModuleConfig $moduleConfig,
                ?ProtocolCache $protocolCache,
                LoggerService $loggerService,
                private readonly Closure $clock,
            ) {
                parent::__construct($oAuth2, $x509, $moduleConfig, $protocolCache, $loggerService);
            }


            protected function currentTime(): float
            {
                return ($this->clock)();
            }
        };
    }


    protected function request(?string $attestation, ?string $pop): ServerRequestInterface
    {
        $request = new ServerRequest('POST', self::TOKEN_URL);

        if ($attestation !== null) {
            $request = $request->withHeader('OAuth-Client-Attestation', $attestation);
        }

        return $pop === null ? $request : $request->withHeader('OAuth-Client-Attestation-PoP', $pop);
    }


    /**
     * Parses and verifies, for the given client or the one the builder registers.
     *
     * @throws \Throwable
     */
    protected function verify(
        ?string $attestation = null,
        ?string $pop = null,
        ?ClientEntity $client = null,
        ?ClientAttestationVerifier $sut = null,
    ): PresentedClientAttestation {
        $sut ??= $this->sut();

        $presented = $sut->parse(
            $this->request($attestation ?? $this->builder->attestation(), $pop ?? $this->builder->pop()),
        );
        $this->assertInstanceOf(PresentedClientAttestation::class, $presented);

        $sut->verify($presented, $client ?? $this->builder->client());

        return $presented;
    }


    /**
     * @throws \Throwable
     */
    protected function assertRefused(
        string $expectedMessage,
        ?string $attestation = null,
        ?string $pop = null,
        ?ClientEntity $client = null,
    ): void {
        try {
            $this->verify($attestation, $pop, $client);
        } catch (AuthorizationException $exception) {
            $this->assertStringContainsString($expectedMessage, $exception->getMessage());
            return;
        }

        $this->fail('The attestation was accepted.');
    }


    public function testTellsWhetherARequestPresentsAClientAttestation(): void
    {
        $sut = $this->sut();

        $this->assertFalse($sut->presentsClientAttestation($this->request(null, null)));
        $this->assertTrue($sut->presentsClientAttestation($this->request('x', null)));
        $this->assertTrue($sut->presentsClientAttestation($this->request(null, 'x')));
        $this->assertTrue($sut->presentsClientAttestation($this->request('x', 'y')));
    }


    public function testParsesNothingFromARequestWithoutEitherField(): void
    {
        $this->assertNull($this->sut()->parse($this->request(null, null)));
    }


    /**
     * @throws \Throwable
     */
    public function testAcceptsAnAttestationAndPoPEveryCheckAccepts(): void
    {
        $presented = $this->verify();

        $this->assertSame(ClientAttestationBuilder::CLIENT_ID, $presented->getClientId());
        $this->assertSame(
            $this->builder->instanceKey->toPublic()->thumbprint('sha256'),
            $presented->getInstanceKeyThumbprint(),
        );
        $this->assertContains(
            ['level' => 'debug', 'message' => 'Client Attestation accepted.', 'context' => [
                'client_id' => ClientAttestationBuilder::CLIENT_ID,
                'jkt' => $presented->getInstanceKeyThumbprint(),
            ]],
            $this->logRecords,
        );
    }


    /**
     * Section 9 check 1: exactly one field of each, each holding one JWT.
     *
     * @return array<string,array{\Closure, string}>
     */
    public static function malformedFieldsProvider(): array
    {
        $request = static fn(): ServerRequestInterface => new ServerRequest('POST', self::TOKEN_URL);

        return [
            'an attestation without a PoP' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation', $b->attestation()),
                'carries no OAuth-Client-Attestation-PoP header field',
            ],
            'a PoP without an attestation' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation-PoP', $b->pop()),
                'carries no OAuth-Client-Attestation header field',
            ],
            'two attestations' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation', [$b->attestation(), $b->attestation()])
                    ->withHeader('OAuth-Client-Attestation-PoP', $b->pop()),
                'more than one OAuth-Client-Attestation header field',
            ],
            'two PoPs' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation', $b->attestation())
                    ->withHeader('OAuth-Client-Attestation-PoP', [$b->pop(), $b->pop()]),
                'more than one OAuth-Client-Attestation-PoP header field',
            ],
            'two attestations joined into one field' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation', $b->attestation() . ', ' . $b->attestation())
                    ->withHeader('OAuth-Client-Attestation-PoP', $b->pop()),
                'The OAuth-Client-Attestation header field does not hold one JWT',
            ],
            'an empty PoP' => [
                static fn(ClientAttestationBuilder $b): ServerRequestInterface => $request()
                    ->withHeader('OAuth-Client-Attestation', $b->attestation())
                    ->withHeader('OAuth-Client-Attestation-PoP', ''),
                'The OAuth-Client-Attestation-PoP header field does not hold one JWT',
            ],
        ];
    }


    /**
     * @param \Closure $request
     */
    #[DataProvider('malformedFieldsProvider')]
    public function testRefusesFieldsWhichAreNotOneJwtEach(Closure $request, string $expectedMessage): void
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage($expectedMessage);

        $this->sut()->parse($request($this->builder));
    }


    /**
     * What the library refuses when it parses either JWT: section 9 checks 2, 3 and 6, an attestation which has
     * expired, and an `iat` too far ahead. Among them two of the conformance suite's negative cases: an attestation
     * past its `exp`, and one without `sub`.
     *
     * @return array<string,array{\Closure, string}>
     */
    public static function refusedByTheLibraryProvider(): array
    {
        return [
            'an attestation without sub' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(['sub' => null]), $b->pop()],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation past its exp' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(['iat' => time() - 900, 'nbf' => time() - 900, 'exp' => time() - 120]),
                    $b->pop(),
                ],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation without exp' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(['exp' => null]), $b->pop()],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation without cnf' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(['cnf' => null]), $b->pop()],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation whose cnf holds a private key' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(['cnf' => ['jwk' => $b->instanceKey->all()]]),
                    $b->pop(),
                ],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation of another typ' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->rawJws(
                        [
                            'iss' => ClientAttestationBuilder::ATTESTER,
                            'sub' => ClientAttestationBuilder::CLIENT_ID,
                            'exp' => time() + 300,
                            'cnf' => ['jwk' => $b->instanceKey->toPublic()->all()],
                        ],
                        ['alg' => 'ES256', 'typ' => 'jwt'],
                        ClientAttestationBuilder::jwk($b->attesterKey),
                    ),
                    $b->pop(),
                ],
                'The Client Attestation is not a well-formed',
            ],
            'an attestation issued in the future' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(['iat' => time() + 600]), $b->pop()],
                'The Client Attestation is not a well-formed',
            ],
            'a PoP without jti' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(), $b->pop(['jti' => null])],
                'The Client Attestation PoP is not a well-formed',
            ],
            'a PoP without aud' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(), $b->pop(['aud' => null])],
                'The Client Attestation PoP is not a well-formed',
            ],
            'a PoP without iat' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(), $b->pop(['iat' => null])],
                'The Client Attestation PoP is not a well-formed',
            ],
            'a PoP created more than a minute ahead' => [
                static fn(ClientAttestationBuilder $b): array => [$b->attestation(), $b->pop(['iat' => time() + 120])],
                'The Client Attestation PoP is not a well-formed',
            ],
            'a PoP of another typ' => [
                static fn(ClientAttestationBuilder $b): array => [
                    $b->attestation(),
                    $b->rawJws(
                        [
                            'iss' => ClientAttestationBuilder::CLIENT_ID,
                            'aud' => ClientAttestationBuilder::ISSUER,
                            'jti' => 'pop-1',
                            'iat' => time(),
                        ],
                        ['alg' => 'ES256', 'typ' => 'dpop+jwt'],
                        $b->instanceKey,
                    ),
                ],
                'The Client Attestation PoP is not a well-formed',
            ],
        ];
    }


    /**
     * @param \Closure $tokens
     */
    #[DataProvider('refusedByTheLibraryProvider')]
    public function testRefusesWhatTheLibraryRefuses(Closure $tokens, string $expectedMessage): void
    {
        [$attestation, $pop] = $tokens($this->builder);

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage($expectedMessage);

        $this->sut()->parse($this->request($attestation, $pop));
    }


    /**
     * Check 4, local policy, for either JWT on its own.
     *
     * @throws \Throwable
     */
    public function testRefusesAlgorithmsTheModuleDoesNotAccept(): void
    {
        $this->acceptedAlgorithms = ['ES384'];
        $this->assertRefused('The Client Attestation is signed with an algorithm which is not accepted (ES256).');

        // The attestation signed with ES256 and a PoP with ES384, by a P-384 instance key.
        $this->acceptedAlgorithms = ['ES256'];
        $instanceKey = JWKFactory::createECKey('P-384');
        $this->assertRefused(
            'The Client Attestation PoP is signed with an algorithm which is not accepted (ES384).',
            $this->builder->attestation(instanceKey: $instanceKey),
            $this->builder->pop(signingKey: $instanceKey, algorithm: SignatureAlgorithmEnum::ES384),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesAClientWhichIsNotRegisteredForAttestation(): void
    {
        foreach ([null, 'private_key_jwt', 'none'] as $method) {
            $this->assertRefused(
                'The client is not registered to authenticate with attest_jwt_client_auth.',
                client: $this->builder->client(tokenEndpointAuthMethod: $method),
            );
        }
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesAClientWithoutUsableTrust(): void
    {
        $this->assertRefused('The client has no client attestation trust', client: $this->builder->client(null));
        $this->assertRefused(
            'The client attestation trust of the client can not be read',
            client: $this->builder->client(['attester' => ClientAttestationBuilder::ATTESTER]),
        );
    }


    /**
     * Check 5: the attester the client trusts, by its `iss`, compared exactly.
     *
     * @throws \Throwable
     */
    public function testRefusesAnAttestationOfAnotherAttester(): void
    {
        foreach (['https://provider-b.example.org', ClientAttestationBuilder::ATTESTER . '/'] as $attester) {
            $this->assertRefused(
                'The Client Attestation was not issued by the attester of the client',
                $this->builder->attestation(['iss' => $attester]),
            );
        }
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesAnAttestationWithoutACertificateChain(): void
    {
        $this->assertRefused(
            'The Client Attestation carries no x5c header parameter',
            $this->builder->attestation(header: ['x5c' => null]),
        );
    }


    /**
     * @throws \Throwable
     */
    public function testRefusesTrustAnchorsWhichCanNotBeUsed(): void
    {
        // Not a certificate, and a certificate which is not a CA's.
        foreach (['not a certificate', CertificateBuilder::pem($this->builder->attesterDer)] as $trustAnchors) {
            $this->assertRefused(
                'The trust anchors in the client attestation trust of the client can not be used',
                client: $this->builder->client($this->builder->trust(['trust_anchors' => $trustAnchors])),
            );
        }
    }


    /**
     * A chain under another root, and the client's own chain with its issuing CA left out.
     *
     * @throws \Throwable
     */
    public function testRefusesAChainWhichDoesNotValidateAgainstTheClientsTrustAnchors(): void
    {
        $otherRootKey = CertificateBuilder::ecKey();
        [$otherCaKey, $otherCaDer] = $this->builder->issuingCa('CN=Other Issuing CA', $otherRootKey, 'CN=Other Root');
        [$attesterKey, $attesterDer] = $this->builder->attesterCertificate($otherCaKey, issuer: 'CN=Other Issuing CA');

        $this->assertRefused(
            'The certificate chain of the Client Attestation does not validate against the trust anchors',
            $this->builder->attestation(
                header: ['x5c' => [base64_encode($attesterDer), base64_encode($otherCaDer)]],
                signingKey: ClientAttestationBuilder::jwk($attesterKey),
            ),
        );

        $this->assertRefused(
            'The certificate chain of the Client Attestation does not validate against the trust anchors',
            $this->builder->attestation(header: ['x5c' => [base64_encode($this->builder->attesterDer)]]),
        );
    }


    /**
     * D36: two issuing CAs of one root, each certifying a provider of the same subject and names. The client pins
     * the first, so the second's provider can not sign for it, nor the first's for a client pinning the second.
     *
     * @throws \Throwable
     */
    public function testRefusesAProviderOfTheSameNameUnderASiblingIssuingCa(): void
    {
        [$siblingCaKey, $siblingCaDer] = $this->builder->issuingCa();
        [$siblingAttesterKey, $siblingAttesterDer] = $this->builder->attesterCertificate($siblingCaKey);

        $siblingsAttestation = fn(): string => $this->builder->attestation(
            header: ['x5c' => [base64_encode($siblingAttesterDer), base64_encode($siblingCaDer)]],
            signingKey: ClientAttestationBuilder::jwk($siblingAttesterKey),
        );

        $this->assertRefused(
            'The certificate of the Client Attestation was not issued by the issuing CA the client pins.',
            $siblingsAttestation(),
        );

        $clientPinningTheSibling = $this->builder->client(
            $this->builder->trust(['issuing_ca_public_key_sha256' => $this->builder->publicKeySha256($siblingCaDer)]),
        );
        $this->assertRefused(
            'The certificate of the Client Attestation was not issued by the issuing CA the client pins.',
            client: $clientPinningTheSibling,
        );

        // Each is accepted for the client which pins its own issuing CA.
        $this->verify($siblingsAttestation(), client: $clientPinningTheSibling);
    }


    /**
     * D36: two providers certified by one issuing CA. The second asserts the first's attester as its `iss`, which
     * nothing binds; its certificate does not name the first, so it can not sign for the first's client.
     *
     * @throws \Throwable
     */
    public function testRefusesAnotherProviderOfTheSameIssuingCaAssertingTheAttester(): void
    {
        [$providerBKey, $providerBDer] = $this->builder->attesterCertificate(
            $this->builder->issuingCaKey,
            'CN=Wallet Provider B,O=Example',
            uri: 'https://provider-b.example.org',
            host: 'provider-b.example.org',
        );
        $providerBsAttestation = fn(array $claims = []): string => $this->builder->attestation(
            $claims,
            header: ['x5c' => [base64_encode($providerBDer), base64_encode($this->builder->issuingCaDer)]],
            signingKey: ClientAttestationBuilder::jwk($providerBKey),
        );

        $pins = [
            'san_uri' => ClientAttestationBuilder::ATTESTER,
            'san_dns' => ClientAttestationBuilder::ATTESTER_HOST,
            'subject_dn' => ClientAttestationBuilder::ATTESTER_SUBJECT,
        ];

        foreach ($pins as $type => $value) {
            $this->assertRefused(
                sprintf('of the Client Attestation does not name the attester the client pins (%s).', $type),
                $providerBsAttestation(),
                client: $this->builder->client(
                    $this->builder->trust(['attester_identity' => ['type' => $type, 'value' => $value]]),
                ),
            );
        }

        // Provider B is accepted for a client trusting it, under the same issuing CA.
        $this->verify(
            $providerBsAttestation(['iss' => 'https://provider-b.example.org']),
            client: $this->builder->client($this->builder->trust([
                'attester' => 'https://provider-b.example.org',
                'attester_identity' => ['type' => 'san_dns', 'value' => 'provider-b.example.org'],
            ])),
        );
    }


    /**
     * Every identity type, the DNS name without regard to case.
     *
     * @throws \Throwable
     */
    public function testAcceptsTheAttesterNamedByEveryIdentityType(): void
    {
        $pins = [
            ['san_uri', ClientAttestationBuilder::ATTESTER],
            ['san_dns', strtoupper(ClientAttestationBuilder::ATTESTER_HOST)],
            ['subject_dn', ClientAttestationBuilder::ATTESTER_SUBJECT],
        ];

        foreach ($pins as [$type, $value]) {
            $this->verify(
                client: $this->builder->client(
                    $this->builder->trust(['attester_identity' => ['type' => $type, 'value' => $value]]),
                ),
            );
        }

        $this->addToAssertionCount(1);
    }


    /**
     * An attestation whose signature is not the leaf's: one of the conformance suite's negative cases.
     *
     * @throws \Throwable
     */
    public function testRefusesAnAttestationNotSignedByItsCertificatesKey(): void
    {
        $this->assertRefused(
            'The Client Attestation signature does not verify with the key of its certificate',
            $this->builder->attestation(signingKey: JWKFactory::createECKey('P-256')),
        );

        // The signature of a valid attestation tampered with.
        $attestation = $this->builder->attestation();
        $this->assertRefused(
            'The Client Attestation signature does not verify with the key of its certificate',
            substr($attestation, 0, -4) . (str_ends_with($attestation, 'AAAA') ? 'BBBB' : 'AAAA'),
        );
    }


    /**
     * Check 7: a PoP signed by a key other than `cnf.jwk`, and one tampered with (the conformance suite's two PoP
     * signature cases); rule 4, its `iss` the attestation's `sub`.
     *
     * @throws \Throwable
     */
    public function testRefusesAPopWhichDoesNotVerifyWithTheClientInstanceKey(): void
    {
        $this->assertRefused(
            'The Client Attestation PoP does not verify with the Client Instance Key',
            pop: $this->builder->pop(signingKey: JWKFactory::createECKey('P-256')),
        );

        $pop = $this->builder->pop();
        $this->assertRefused(
            'The Client Attestation PoP does not verify with the Client Instance Key',
            pop: substr($pop, 0, -4) . (str_ends_with($pop, 'AAAA') ? 'BBBB' : 'AAAA'),
        );

        $this->assertRefused(
            'The Client Attestation PoP does not verify with the Client Instance Key',
            pop: $this->builder->pop(['iss' => 'wallet-b']),
        );
    }


    /**
     * Check 10: the PoP's `aud` names this issuer, compared exactly; one of the conformance suite's negative cases.
     *
     * @throws \Throwable
     */
    public function testRefusesAPopForAnotherAudience(): void
    {
        foreach (['https://other.example.org', ClientAttestationBuilder::ISSUER . '/', self::TOKEN_URL] as $audience) {
            $this->assertRefused(
                'The Client Attestation PoP is not addressed to this issuer (aud).',
                pop: $this->builder->pop(['aud' => $audience]),
            );
        }

        $this->verify(
            pop: $this->builder->pop(['aud' => ['https://other.example.org', ClientAttestationBuilder::ISSUER]]),
        );
    }


    /**
     * An attestation which expires while its certificate path is validated is refused: the clock is read after.
     *
     * @throws \Throwable
     */
    public function testRefusesAnAttestationWhichExpiredWhileItsPathWasValidated(): void
    {
        $this->leeway = 'PT10S';
        $expiresAt = time() + 5;
        $attestation = $this->builder->attestation(['exp' => $expiresAt]);

        $this->nowAfterPathValidation = $expiresAt + 10.0;
        $this->assertRefused('The Client Attestation has expired.', $attestation);

        $this->hasValidatedPath = false;
        $this->nowAfterPathValidation = $expiresAt + 9.999;
        $this->verify($attestation);
    }


    /**
     * Checks 9 and 12: the PoP's `iat` within a minute of now either way, the bounds included, on the clock read
     * after the path validation.
     *
     * @throws \Throwable
     */
    public function testRefusesAPopCreatedOutsideTheWindow(): void
    {
        $issuedAt = time();

        $this->nowAfterPathValidation = $issuedAt + 60.001;
        $this->assertRefused(
            'The Client Attestation PoP was not created within the accepted time window.',
            pop: $this->builder->pop(['iat' => $issuedAt]),
        );

        $this->hasValidatedPath = false;
        $this->nowAfterPathValidation = $issuedAt - 60.001;
        $this->assertRefused(
            'The Client Attestation PoP was not created within the accepted time window.',
            pop: $this->builder->pop(['iat' => $issuedAt]),
        );

        foreach ([$issuedAt + 60.0, $issuedAt - 60.0] as $now) {
            $this->hasValidatedPath = false;
            $this->nowAfterPathValidation = $now;
            $this->verify(pop: $this->builder->pop(['iat' => $issuedAt]));
        }
    }


    /**
     * A PoP's `exp` is checked when it has one, the window being its leeway.
     *
     * @throws \Throwable
     */
    public function testRefusesAPopWhichStatesItHasExpired(): void
    {
        $issuedAt = time();
        $pop = $this->builder->pop(['iat' => $issuedAt, 'exp' => $issuedAt - 10]);

        $this->nowAfterPathValidation = $issuedAt + 50.0;
        $this->assertRefused('The Client Attestation PoP has expired.', pop: $pop);

        $this->hasValidatedPath = false;
        $this->nowAfterPathValidation = $issuedAt + 49.999;
        $this->verify(pop: $pop);
    }


    /**
     * Check 12: the same PoP is refused the second time, a fresh one of the same instance accepted.
     *
     * @throws \Throwable
     */
    public function testRefusesAReplayedPop(): void
    {
        $sut = $this->sut();
        $attestation = $this->builder->attestation();
        $pop = $this->builder->pop(['jti' => 'pop-1']);

        $this->verify($attestation, $pop, sut: $sut);

        try {
            $this->verify($attestation, $pop, sut: $sut);
            $this->fail('A replayed PoP was accepted.');
        } catch (AuthorizationException $exception) {
            $this->assertSame('The Client Attestation PoP has been used before.', $exception->getMessage());
        }

        $this->verify($attestation, $this->builder->pop(['jti' => 'pop-2']), sut: $sut);
    }


    /**
     * The replay record is keyed on the client, the instance key and the `jti`: another instance using the same
     * `jti` is not refused for it.
     *
     * @throws \Throwable
     */
    public function testKeysTheReplayRecordOnTheInstanceKey(): void
    {
        $sut = $this->sut();
        $otherInstanceKey = JWKFactory::createECKey('P-256');

        $this->verify(pop: $this->builder->pop(['jti' => 'pop-1']), sut: $sut);
        $this->verify(
            $this->builder->attestation(instanceKey: $otherInstanceKey),
            $this->builder->pop(['jti' => 'pop-1'], $otherInstanceKey),
            sut: $sut,
        );

        $this->addToAssertionCount(1);
    }


    /**
     * A refused PoP is not remembered: the same one is refused for the same reason again, not as a replay.
     *
     * @throws \Throwable
     */
    public function testRemembersOnlyAPopWhichPassedEveryOtherCheck(): void
    {
        $sut = $this->sut();
        $pop = $this->builder->pop(['jti' => 'pop-1', 'aud' => 'https://other.example.org']);

        foreach ([1, 2] as $attempt) {
            try {
                $this->verify(pop: $pop, sut: $sut);
                $this->fail('A PoP for another audience was accepted.');
            } catch (AuthorizationException $exception) {
                $this->assertStringContainsString(
                    'not addressed to this issuer',
                    $exception->getMessage(),
                    (string)$attempt,
                );
            }
        }
    }


    /**
     * Without a protocol cache kept across requests nothing is remembered, as for DPoP proofs.
     *
     * @throws \Throwable
     */
    public function testChecksNoReplayWithoutAProtocolCacheKeptAcrossRequests(): void
    {
        $attestation = $this->builder->attestation();
        $pop = $this->builder->pop();

        $sut = $this->sut(withoutCache: true);
        $this->verify($attestation, $pop, sut: $sut);
        $this->verify($attestation, $pop, sut: $sut);

        $this->isCacheKeptAcrossRequests = false;
        $sut = $this->sut();
        $this->verify($attestation, $pop, sut: $sut);
        $this->verify($attestation, $pop, sut: $sut);

        $this->assertContains(
            'Client Attestation PoPs are not checked for replay, since no protocol cache which keeps entries ' .
            'across requests is configured.',
            array_column($this->logRecords, 'message'),
        );
    }


    /**
     * A path validation which can not run at all, here for a temporary directory which does not exist, says nothing
     * about the attestation: the OP's own failure, not a refusal.
     *
     * @throws \Throwable
     */
    public function testFailsAsTheOpsOwnFailureWhenThePathValidationCanNotRun(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to validate the certificate chain of the Client Attestation: ');

        $missingDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ht4-missing-' . bin2hex(random_bytes(8));

        $this->verify(sut: $this->sut(temporaryDirectory: $missingDirectory));
    }


    /**
     * A cache which can not be asked, does not store the record, or does not read it back fails the request as
     * the OP's own failure.
     *
     * @return array<string,array{\Closure}>
     */
    public static function failingCacheProvider(): array
    {
        return [
            'a cache which throws' => [
                static function (TestCase $test): ProtocolCache {
                    $cache = $test->getMockBuilder(ProtocolCache::class)->disableOriginalConstructor()->getMock();
                    $cache->method('has')->willThrowException(new RuntimeException('cache down'));
                    return $cache;
                },
            ],
            'a cache which does not store' => [
                static function (TestCase $test): ProtocolCache {
                    $cache = $test->getMockBuilder(ProtocolCache::class)->disableOriginalConstructor()->getMock();
                    $cache->method('has')->willReturn(false);
                    $cache->method('set')->willReturn(false);
                    return $cache;
                },
            ],
            'a cache which forgets' => [
                static function (TestCase $test): ProtocolCache {
                    $cache = $test->getMockBuilder(ProtocolCache::class)->disableOriginalConstructor()->getMock();
                    $cache->method('has')->willReturn(false);
                    $cache->method('set')->willReturn(true);
                    return $cache;
                },
            ],
        ];
    }


    /**
     * @param \Closure $cache
     * @throws \Throwable
     */
    #[DataProvider('failingCacheProvider')]
    public function testFailsAsTheOpsOwnFailureWhenTheCacheDoesNotKeepTheRecord(Closure $cache): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Unable to check the Client Attestation PoP for replay');

        $this->verify(sut: $this->sut($cache($this)));
    }
}
