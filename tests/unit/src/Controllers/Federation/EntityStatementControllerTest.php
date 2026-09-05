<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Federation;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Controllers\Federation\EntityStatementController;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientRegistrationTypesEnum;
use SimpleSAML\OpenID\Codebooks\ContentTypesEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Codebooks\HttpHeadersEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\EntityStatementFetcher;
use SimpleSAML\OpenID\Federation\Factories\EntityStatementFactory;
use SimpleSAML\OpenID\Federation\Factories\TrustMarkFactory;
use SimpleSAML\OpenID\Federation\TrustMark;
use SimpleSAML\OpenID\Federation\TrustMarkFetcher;
use SimpleSAML\OpenID\Helpers as OpenIdHelpers;
use SimpleSAML\OpenID\Helpers\Random;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use SimpleSAML\OpenID\Jwks\JwksDecorator;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The entity configuration statement is how every other federation participant learns this OP exists, so
 * what these tests hold to is the content of the statement rather than the fact that one was produced.
 *
 * The signing itself belongs to the library and is mocked, but what is handed to it is not: the payload,
 * the header, the private key and the algorithm are all captured and asserted, since choosing them is the
 * part this module is responsible for.
 */
#[CoversClass(EntityStatementController::class)]
#[AllowMockObjectsWithoutExpectations]
class EntityStatementControllerTest extends TestCase
{
    protected const string ISSUER = 'https://op.example.org';

    protected const string SIGNED_TOKEN = 'signed.entity.configuration';

    protected const string CACHED_TOKEN = 'cached.entity.configuration';

    protected const string KEY_ID = 'federation-key-01';

    protected const string SECOND_KEY_ID = 'federation-key-02';

    protected const string JTI = 'random-jti';

    protected const string TRUST_MARK_TYPE = 'https://ta.example.org/trust-mark-types/member';

    protected const string TRUST_MARK_ISSUER = 'https://tm-issuer.example.org';

    protected const string TRUST_MARK_TOKEN = 'static.trust.mark.token';

    /** The statement duration a test configures, chosen so that a hardcoded default would not match it. */
    protected const string STATEMENT_DURATION = 'PT90M';


    protected MockObject $moduleConfigMock;

    protected MockObject $jwksMock;

    protected MockObject $opMetadataServiceMock;

    protected MockObject $helpersMock;

    protected MockObject $routesMock;

    protected MockObject $federationMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $federationCacheMock;

    /** The two configured key pairs, so that "the first one signs" is a claim a test can check. */
    protected MockObject $firstPrivateKey;

    protected MockObject $firstPublicKey;

    protected MockObject $secondPublicKey;

    /** The Trust Mark issuer's own configuration statement, as handed to the Trust Mark fetcher. */
    protected MockObject $trustMarkIssuerStatement;

    /**
     * Scenario state, read through the callbacks wired in setUp() so a test can say what the deployment
     * looks like without re-stubbing a mock which already has a matcher.
     */
    protected ?string $cachedToken = null;

    /** @var array<string,mixed> */
    protected array $commonMetadata = [];

    /** @var string[]|null */
    protected ?array $authorityHints = null;

    /** @var string[]|null */
    protected ?array $trustMarkTokens = null;

    /** @var array<string,string>|null */
    protected ?array $dynamicTrustMarks = null;

    /** @var array<string,string> Trust Mark token => the subject it was issued for. */
    protected array $trustMarkSubjects = [];

    protected ?Throwable $issuerStatementFailure = null;

    protected ?Throwable $trustMarkFetchFailure = null;

    /** @var array<string,mixed> */
    protected array $opMetadata = [];

    /** What was handed to the statement factory to sign. */
    protected ?array $signedPayload = null;

    protected ?array $signedHeader = null;

    protected mixed $signedWithKey = null;

    protected mixed $signedWithAlgorithm = null;

    protected int $signedCount = 0;

    /** @var array<int,mixed> The keys the JWKS claim was built from. */
    protected array $publishedJwkDecorators = [];

    /** @var array<int,array{subject:string,statement:mixed}> */
    protected array $trustMarkFetches = [];

    /** @var string[] The entities whose configuration statement was fetched. */
    protected array $issuerStatementFetches = [];

    /** How many times the clock has been read, so consecutive readings can differ. */
    protected int $clockReads = 0;

    /** @var string[] The cache keys the statement was looked up under. */
    protected array $cacheReadKeys = [];

    /** @var array<int,array{token:string,ttl:mixed,keys:array}> */
    protected array $cacheWrites = [];

    protected DateTimeImmutable $now;


    protected function setUp(): void
    {
        $this->now = new DateTimeImmutable('2026-09-05 10:00:00', new DateTimeZone('UTC'));

        $this->cachedToken = null;
        $this->commonMetadata = [
            'getOrganizationName' => 'Example Org',
            'getDisplayName' => 'Example OP',
            'getDescription' => 'An OpenID Provider',
            'getKeywords' => ['openid', 'op'],
            'getContacts' => ['ops@example.org'],
            'getLogoUri' => 'https://example.org/logo.png',
            'getPolicyUri' => 'https://example.org/policy',
            'getInformationUri' => 'https://example.org/info',
            'getOrganizationUri' => 'https://example.org',
        ];
        $this->authorityHints = null;
        $this->trustMarkTokens = null;
        $this->dynamicTrustMarks = null;
        $this->trustMarkSubjects = [self::TRUST_MARK_TOKEN => self::ISSUER];
        $this->issuerStatementFailure = null;
        $this->trustMarkFetchFailure = null;
        $this->opMetadata = ['issuer' => self::ISSUER, 'response_types_supported' => ['code']];
        $this->signedPayload = null;
        $this->signedHeader = null;
        $this->signedWithKey = null;
        $this->signedWithAlgorithm = null;
        $this->signedCount = 0;
        $this->publishedJwkDecorators = [];
        $this->trustMarkFetches = [];
        $this->issuerStatementFetches = [];
        $this->clockReads = 0;
        $this->cacheReadKeys = [];
        $this->cacheWrites = [];

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getFederationEntityStatementDuration')
            ->willReturn(new DateInterval(self::STATEMENT_DURATION));
        $this->moduleConfigMock->method('getFederationEntityStatementCacheDurationForProduced')
            ->willReturn(new DateInterval('PT2M'));
        $this->moduleConfigMock->method('getFederationSignatureKeyPairBag')
            ->willReturn($this->buildSignatureKeyPairBag());

        foreach (array_keys($this->commonMetadata) as $getter) {
            $this->moduleConfigMock->method($getter)->willReturnCallback(
                fn(): mixed => $this->commonMetadata[$getter] ?? null,
            );
        }

        $this->moduleConfigMock->method('getFederationAuthorityHints')
            ->willReturnCallback(fn(): ?array => $this->authorityHints);
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')
            ->willReturnCallback(fn(): ?array => $this->trustMarkTokens);
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willReturnCallback(fn(): ?array => $this->dynamicTrustMarks);

        $this->jwksMock = $this->createMock(Jwks::class);
        $jwksDecoratorMock = $this->createMock(JwksDecorator::class);
        $jwksDecoratorMock->method('jsonSerialize')->willReturn(['keys' => [['kid' => self::KEY_ID]]]);
        $jwksDecoratorFactoryMock = $this->createMock(JwksDecoratorFactory::class);
        $jwksDecoratorFactoryMock->method('fromJwkDecorators')->willReturnCallback(
            function (JwkDecorator ...$jwkDecorators) use ($jwksDecoratorMock): JwksDecorator {
                $this->publishedJwkDecorators = $jwkDecorators;

                return $jwksDecoratorMock;
            },
        );
        $this->jwksMock->method('jwksDecoratorFactory')->willReturn($jwksDecoratorFactoryMock);

        $this->opMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->opMetadataServiceMock->method('getMetadata')
            ->willReturnCallback(fn(): array => $this->opMetadata);

        $this->helpersMock = $this->createMock(Helpers::class);
        $dateTimeHelperMock = $this->createMock(DateTime::class);
        $dateTimeHelperMock->method('getUtc')->willReturnCallback(
            function (): DateTimeImmutable {
                $instant = $this->now->modify(sprintf('+%d seconds', $this->clockReads));
                $this->clockReads++;

                return $instant;
            },
        );
        $this->helpersMock->method('dateTime')->willReturn($dateTimeHelperMock);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newResponse')->willReturnCallback(
            static fn(?string $content, int $status, array $headers): Response => new Response(
                $content,
                $status,
                $headers,
            ),
        );

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->federationCacheMock = $this->createMock(FederationCache::class);
        $this->federationCacheMock->method('get')->willReturnCallback(
            function (mixed $default, string ...$keys): mixed {
                $this->cacheReadKeys = $keys;

                return $this->cachedToken ?? $default;
            },
        );
        $this->federationCacheMock->method('set')->willReturnCallback(
            function (mixed $value, mixed $ttl, string ...$keys): void {
                $this->cacheWrites[] = ['token' => (string)$value, 'ttl' => $ttl, 'keys' => $keys];
            },
        );

        $this->federationMock = $this->createMock(Federation::class);
        $this->federationMock->method('helpers')->willReturn($this->buildOpenIdHelpers());
        $this->federationMock->method('entityStatementFactory')->willReturn($this->buildEntityStatementFactory());

        $trustMarkFactoryMock = $this->createMock(TrustMarkFactory::class);
        $trustMarkFactoryMock->method('fromToken')->willReturnCallback(
            fn(mixed $token): TrustMark => $this->buildTrustMark(
                (string)$token,
                $this->trustMarkSubjects[(string)$token] ?? self::ISSUER,
            ),
        );
        $this->federationMock->method('trustMarkFactory')->willReturn($trustMarkFactoryMock);

        $this->trustMarkIssuerStatement = $this->createMock(EntityStatement::class);
        $entityStatementFetcherMock = $this->createMock(EntityStatementFetcher::class);
        $entityStatementFetcherMock->method('fromCacheOrWellKnownEndpoint')->willReturnCallback(
            function (string $entityId): EntityStatement {
                $this->issuerStatementFetches[] = $entityId;

                if ($this->issuerStatementFailure instanceof Throwable) {
                    throw $this->issuerStatementFailure;
                }

                return $this->trustMarkIssuerStatement;
            },
        );
        $this->federationMock->method('entityStatementFetcher')->willReturn($entityStatementFetcherMock);

        $trustMarkFetcherMock = $this->createMock(TrustMarkFetcher::class);
        $trustMarkFetcherMock->method('fromCacheOrFederationTrustMarkEndpoint')->willReturnCallback(
            function (string $trustMarkType, string $subject, mixed $issuerStatement): TrustMark {
                $this->trustMarkFetches[] = ['subject' => $subject, 'statement' => $issuerStatement];

                if ($this->trustMarkFetchFailure instanceof Throwable) {
                    throw $this->trustMarkFetchFailure;
                }

                return $this->buildTrustMark('dynamic.' . $trustMarkType, self::ISSUER);
            },
        );
        $this->federationMock->method('trustMarkFetcher')->willReturn($trustMarkFetcherMock);
    }


    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?Jwks $jwks = null,
        ?OpMetadataService $opMetadataService = null,
        ?Helpers $helpers = null,
        ?Routes $routes = null,
        ?Federation $federation = null,
        ?LoggerService $loggerService = null,
        ?FederationCache $federationCache = null,
    ): EntityStatementController {
        $moduleConfig ??= $this->moduleConfigMock;
        $jwks ??= $this->jwksMock;
        $opMetadataService ??= $this->opMetadataServiceMock;
        $helpers ??= $this->helpersMock;
        $routes ??= $this->routesMock;
        $federation ??= $this->federationMock;
        $loggerService ??= $this->loggerServiceMock;
        $federationCache ??= $this->federationCacheMock;

        return new EntityStatementController(
            $moduleConfig,
            $jwks,
            $opMetadataService,
            $helpers,
            $routes,
            $federation,
            $loggerService,
            $federationCache,
        );
    }


    /**
     * Two configured pairs, because one cannot show which of them was chosen. The second carries a
     * different algorithm as well as a different key id, so picking the wrong pair is visible in the
     * header and in what was handed to the signer.
     */
    protected function buildSignatureKeyPairBag(): SignatureKeyPairBag
    {
        $this->firstPrivateKey = $this->createMock(JwkDecorator::class);
        $this->firstPublicKey = $this->createMock(JwkDecorator::class);
        $this->secondPublicKey = $this->createMock(JwkDecorator::class);

        return new SignatureKeyPairBag(
            $this->buildSignatureKeyPair(
                self::KEY_ID,
                SignatureAlgorithmEnum::RS256,
                $this->firstPrivateKey,
                $this->firstPublicKey,
            ),
            $this->buildSignatureKeyPair(
                self::SECOND_KEY_ID,
                SignatureAlgorithmEnum::ES256,
                $this->createMock(JwkDecorator::class),
                $this->secondPublicKey,
            ),
        );
    }


    protected function buildSignatureKeyPair(
        string $keyId,
        SignatureAlgorithmEnum $signatureAlgorithm,
        JwkDecorator $privateKey,
        JwkDecorator $publicKey,
    ): SignatureKeyPair {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn($keyId);
        $keyPairMock->method('getPrivateKey')->willReturn($privateKey);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn($signatureAlgorithm);

        return $signatureKeyPairMock;
    }


    protected function buildOpenIdHelpers(): OpenIdHelpers
    {
        $randomMock = $this->createMock(Random::class);
        $randomMock->method('string')->willReturn(self::JTI);

        $openIdHelpersMock = $this->createMock(OpenIdHelpers::class);
        $openIdHelpersMock->method('random')->willReturn($randomMock);

        return $openIdHelpersMock;
    }


    protected function buildEntityStatementFactory(): EntityStatementFactory
    {
        $entityStatementMock = $this->createMock(EntityStatement::class);
        $entityStatementMock->method('getToken')->willReturn(self::SIGNED_TOKEN);

        $entityStatementFactoryMock = $this->createMock(EntityStatementFactory::class);
        $entityStatementFactoryMock->method('fromData')->willReturnCallback(
            function (
                mixed $signingKey,
                mixed $signatureAlgorithm,
                array $payload,
                array $header,
            ) use ($entityStatementMock): EntityStatement {
                $this->signedWithKey = $signingKey;
                $this->signedWithAlgorithm = $signatureAlgorithm;
                $this->signedPayload = $payload;
                $this->signedHeader = $header;
                $this->signedCount++;

                return $entityStatementMock;
            },
        );

        return $entityStatementFactoryMock;
    }


    protected function buildTrustMark(string $token, string $subject): TrustMark
    {
        $trustMarkMock = $this->createMock(TrustMark::class);
        $trustMarkMock->method('getToken')->willReturn($token);
        $trustMarkMock->method('getSubject')->willReturn($subject);
        $trustMarkMock->method('getTrustMarkType')->willReturn(self::TRUST_MARK_TYPE);

        return $trustMarkMock;
    }


    /**
     * The payload this OP asked the library to sign.
     *
     * @throws \Exception
     */
    protected function publishedPayload(): array
    {
        $this->sut()->configuration();

        $this->assertNotNull($this->signedPayload, 'Nothing was signed.');

        return (array)$this->signedPayload;
    }


    /**
     * The federation entity part of the published metadata.
     *
     * @throws \Exception
     */
    protected function publishedFederationEntityMetadata(): array
    {
        $metadata = $this->publishedPayload()[ClaimsEnum::Metadata->value] ?? [];
        $this->assertIsArray($metadata);

        $federationEntity = $metadata[EntityTypesEnum::FederationEntity->value] ?? [];
        $this->assertIsArray($federationEntity);

        return $federationEntity;
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(EntityStatementController::class, $this->sut());
    }


    /**
     * The endpoint is not served at all unless the deployment participates in a federation, and that is
     * settled in the constructor so no route can reach a half-configured controller.
     */
    public function testThrowsIfFederationNotEnabled(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->expects($this->once())->method('getFederationEnabled')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('refused');

        $this->sut(moduleConfig: $moduleConfigMock);
    }


    /**
     * A cached statement is served as it stands. Rebuilding it would produce a statement with a later
     * `iat` and a new `jti` on every fetch, which is what the cache exists to prevent.
     *
     * @throws \Exception
     */
    public function testServesACachedStatementWithoutRebuildingIt(): void
    {
        $this->cachedToken = self::CACHED_TOKEN;

        $response = $this->sut()->configuration();

        $this->assertSame(self::CACHED_TOKEN, $response->getContent());
        $this->assertSame(0, $this->signedCount, 'A cached statement was signed again.');
        $this->assertSame([], $this->cacheWrites, 'A cached statement was written back to the cache.');
    }


    /**
     * @throws \Exception
     */
    public function testBuildsAndSignsAStatementWhenNothingIsCached(): void
    {
        $response = $this->sut()->configuration();

        $this->assertSame(self::SIGNED_TOKEN, $response->getContent());
        $this->assertSame(1, $this->signedCount);
    }


    /**
     * An entity configuration is a statement an entity makes about itself, so both ends of it name this
     * OP. A `sub` which is anything else would make this a subordinate statement about someone else.
     *
     * @throws \Exception
     */
    public function testTheStatementIsAboutThisOpItself(): void
    {
        $payload = $this->publishedPayload();

        $this->assertSame(self::ISSUER, $payload[ClaimsEnum::Iss->value] ?? null);
        $this->assertSame(self::ISSUER, $payload[ClaimsEnum::Sub->value] ?? null);
    }


    /**
     * Issued now and expiring the configured duration later. The duration is deliberately not a round
     * default: a statement lifetime hardcoded in the controller would agree with a default and disagree
     * with this.
     *
     * The clock here advances a second per reading, which makes something visible that a fixed clock
     * hides: the controller reads it twice, once for `iat` and once as the base for `exp`, so the
     * published lifetime is the configured duration plus however long the work between the two readings
     * took. Harmless against a lifetime measured in hours, and pinned as it behaves rather than
     * corrected here -- it is recorded in the release plan as a tidy-up.
     *
     * @throws \Exception
     */
    public function testTheStatementIsIssuedNowAndExpiresAfterTheConfiguredDuration(): void
    {
        $payload = $this->publishedPayload();

        $this->assertSame($this->now->getTimestamp(), $payload[ClaimsEnum::Iat->value] ?? null);
        $this->assertSame(
            $this->now->modify('+1 seconds')->getTimestamp() + 5400,
            $payload[ClaimsEnum::Exp->value] ?? null,
        );
    }


    /**
     * Every configured pair is published so that anything they signed can still be verified, which is
     * the whole of the rollover model. Asserted as the keys handed to the JWKS factory, since a
     * statement which published no keys at all would otherwise look the same here.
     *
     * @throws \Exception
     */
    public function testTheStatementCarriesEveryFederationPublicKeyAndAJti(): void
    {
        $payload = $this->publishedPayload();

        $this->assertSame(
            [$this->firstPublicKey, $this->secondPublicKey],
            $this->publishedJwkDecorators,
        );
        $this->assertSame(['keys' => [['kid' => self::KEY_ID]]], $payload[ClaimsEnum::Jwks->value] ?? null);
        $this->assertSame(self::JTI, $payload[ClaimsEnum::Jti->value] ?? null);
    }


    /**
     * @throws \Exception
     */
    public function testThePublishedCommonMetadataIsWhatWasConfigured(): void
    {
        $federationEntity = $this->publishedFederationEntityMetadata();

        $this->assertSame('Example Org', $federationEntity[ClaimsEnum::OrganizationName->value] ?? null);
        $this->assertSame('Example OP', $federationEntity[ClaimsEnum::DisplayName->value] ?? null);
        $this->assertSame('An OpenID Provider', $federationEntity[ClaimsEnum::Description->value] ?? null);
        $this->assertSame(['openid', 'op'], $federationEntity[ClaimsEnum::Keywords->value] ?? null);
        $this->assertSame(['ops@example.org'], $federationEntity[ClaimsEnum::Contacts->value] ?? null);
        $this->assertSame(
            'https://example.org/logo.png',
            $federationEntity[ClaimsEnum::LogoUri->value] ?? null,
        );
        $this->assertSame(
            'https://example.org/policy',
            $federationEntity[ClaimsEnum::PolicyUri->value] ?? null,
        );
        $this->assertSame(
            'https://example.org/info',
            $federationEntity[ClaimsEnum::InformationUri->value] ?? null,
        );
        $this->assertSame(
            'https://example.org',
            $federationEntity[ClaimsEnum::OrganizationUri->value] ?? null,
        );
    }


    /**
     * What a deployment left unset is absent from the statement rather than published as null. A null
     * `logo_uri` in an entity configuration is not the same as not having one: it is a claim, and a
     * consumer would have to special-case it. Every one of them, since the filter is applied to the set
     * rather than per claim and a single one escaping it would be the bug.
     *
     * @throws \Exception
     */
    public function testCommonMetadataWhichWasNotConfiguredIsAbsentRatherThanNull(): void
    {
        foreach (array_keys($this->commonMetadata) as $getter) {
            $this->commonMetadata[$getter] = null;
        }

        $federationEntity = $this->publishedFederationEntityMetadata();

        $this->assertSame([], $federationEntity);
    }


    /**
     * @throws \Exception
     */
    public function testEachCommonMetadataClaimIsOmittedOnItsOwn(): void
    {
        $this->commonMetadata['getDisplayName'] = null;
        $this->commonMetadata['getPolicyUri'] = null;

        $federationEntity = $this->publishedFederationEntityMetadata();

        $this->assertArrayNotHasKey(ClaimsEnum::DisplayName->value, $federationEntity);
        $this->assertArrayNotHasKey(ClaimsEnum::PolicyUri->value, $federationEntity);
        $this->assertArrayHasKey(ClaimsEnum::OrganizationName->value, $federationEntity);
        $this->assertArrayHasKey(ClaimsEnum::InformationUri->value, $federationEntity);
    }


    /**
     * The OP metadata is the same one served at the discovery endpoint, with the federation-only claim
     * added: this OP registers clients automatically, through their trust chain, and says so here.
     *
     * @throws \Exception
     */
    public function testTheOpMetadataIsPublishedWithAutomaticRegistrationAdvertised(): void
    {
        $metadata = $this->publishedPayload()[ClaimsEnum::Metadata->value] ?? [];
        $this->assertIsArray($metadata);

        $openIdProvider = $metadata[EntityTypesEnum::OpenIdProvider->value] ?? [];
        $this->assertIsArray($openIdProvider);

        $this->assertSame(self::ISSUER, $openIdProvider['issuer'] ?? null);
        $this->assertSame(['code'], $openIdProvider['response_types_supported'] ?? null);
        $this->assertSame(
            [ClientRegistrationTypesEnum::Automatic->value],
            $openIdProvider[ClaimsEnum::ClientRegistrationTypesSupported->value] ?? null,
        );
    }


    /**
     * @throws \Exception
     */
    public function testAuthorityHintsArePublishedWhenThereAreAny(): void
    {
        $this->authorityHints = ['https://intermediate.example.org/'];

        $this->assertSame(
            ['https://intermediate.example.org/'],
            $this->publishedPayload()[ClaimsEnum::AuthorityHints->value] ?? null,
        );
    }


    /**
     * A trust anchor has no authorities above it, and an entity which is not yet part of a federation has
     * none either. Publishing an empty list would say something different from saying nothing.
     *
     * @throws \Exception
     */
    #[DataProvider('nothingConfiguredDataProvider')]
    public function testTheAuthorityHintsClaimIsAbsentWhenThereAreNone(?array $authorityHints): void
    {
        $this->authorityHints = $authorityHints;

        $this->assertArrayNotHasKey(ClaimsEnum::AuthorityHints->value, $this->publishedPayload());
    }


    /**
     * @return array<string,array{?array}>
     */
    public static function nothingConfiguredDataProvider(): array
    {
        return [
            'not configured' => [null],
            'configured empty' => [[]],
        ];
    }


    /**
     * @throws \Exception
     */
    public function testConfiguredTrustMarksArePublished(): void
    {
        $this->trustMarkTokens = [self::TRUST_MARK_TOKEN];

        $this->assertSame(
            [
                [
                    ClaimsEnum::TrustMarkType->value => self::TRUST_MARK_TYPE,
                    ClaimsEnum::TrustMark->value => self::TRUST_MARK_TOKEN,
                ],
            ],
            $this->publishedPayload()[ClaimsEnum::TrustMarks->value] ?? null,
        );
    }


    /**
     * Pinned as it stands, not endorsed. A Trust Mark issued for another entity is a misconfiguration and
     * this OP must not publish it -- but refusing it this way fails the whole entity configuration, and
     * that statement is how every other participant learns this OP exists. Note the asymmetry with the
     * dynamic Trust Marks below, where a failure is logged and skipped. Recorded in the release plan as a
     * queued fix; when it is made, this test changes with it.
     *
     * @throws \Exception
     */
    public function testRefusesToPublishATrustMarkIssuedForAnotherEntity(): void
    {
        $this->trustMarkTokens = [self::TRUST_MARK_TOKEN];
        $this->trustMarkSubjects[self::TRUST_MARK_TOKEN] = 'https://someone-else.example.org';

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('not intended for this entity');

        $this->sut()->configuration();
    }


    /**
     * Fetched for this OP, from the issuer's own configuration statement. Both matter: a Trust Mark
     * fetched for another subject would not be about this entity, and the issuer statement is what says
     * where the Trust Mark endpoint is.
     *
     * @throws \Exception
     */
    public function testTrustMarksNamedForDynamicFetchingAreFetchedForThisOpAndPublished(): void
    {
        $this->dynamicTrustMarks = [self::TRUST_MARK_TYPE => self::TRUST_MARK_ISSUER];

        $payload = $this->publishedPayload();

        $this->assertSame(
            [
                [
                    ClaimsEnum::TrustMarkType->value => self::TRUST_MARK_TYPE,
                    ClaimsEnum::TrustMark->value => 'dynamic.' . self::TRUST_MARK_TYPE,
                ],
            ],
            $payload[ClaimsEnum::TrustMarks->value] ?? null,
        );

        $this->assertSame([self::TRUST_MARK_ISSUER], $this->issuerStatementFetches);
        $this->assertCount(1, $this->trustMarkFetches);
        $this->assertSame(self::ISSUER, $this->trustMarkFetches[0]['subject']);
        $this->assertSame($this->trustMarkIssuerStatement, $this->trustMarkFetches[0]['statement']);
    }


    /**
     * Neither reaching the Trust Mark issuer nor reaching its Trust Mark endpoint may stop this OP
     * publishing its own configuration. The failure is logged, that Trust Mark is left out, and
     * everything else is still served.
     *
     * @throws \Exception
     */
    #[DataProvider('trustMarkFetchFailureDataProvider')]
    public function testATrustMarkWhichCannotBeFetchedIsLoggedAndLeftOut(string $failingStep): void
    {
        $this->dynamicTrustMarks = [self::TRUST_MARK_TYPE => self::TRUST_MARK_ISSUER];
        $failure = new RuntimeException('Issuer unreachable.');

        if ($failingStep === 'issuer configuration') {
            $this->issuerStatementFailure = $failure;
        } else {
            $this->trustMarkFetchFailure = $failure;
        }

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Issuer unreachable.'),
                $this->callback(
                    static fn(array $context): bool => ($context['trustMarkType'] ?? null) === self::TRUST_MARK_TYPE,
                ),
            );

        $payload = $this->publishedPayload();

        $this->assertArrayNotHasKey(ClaimsEnum::TrustMarks->value, $payload);
        $this->assertSame(self::ISSUER, $payload[ClaimsEnum::Iss->value] ?? null);
    }


    /**
     * @return array<string,array{string}>
     */
    public static function trustMarkFetchFailureDataProvider(): array
    {
        return [
            'the issuer configuration cannot be fetched' => ['issuer configuration'],
            'the Trust Mark endpoint cannot be reached' => ['trust mark endpoint'],
        ];
    }


    /**
     * The two sources are published together rather than one replacing the other.
     *
     * @throws \Exception
     */
    public function testConfiguredAndFetchedTrustMarksArePublishedTogether(): void
    {
        $this->trustMarkTokens = [self::TRUST_MARK_TOKEN];
        $this->dynamicTrustMarks = [self::TRUST_MARK_TYPE => self::TRUST_MARK_ISSUER];

        $trustMarks = $this->publishedPayload()[ClaimsEnum::TrustMarks->value] ?? null;

        $this->assertIsArray($trustMarks);
        $this->assertCount(2, $trustMarks);
        $this->assertSame(
            [self::TRUST_MARK_TOKEN, 'dynamic.' . self::TRUST_MARK_TYPE],
            array_column($trustMarks, ClaimsEnum::TrustMark->value),
        );
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('nothingConfiguredDataProvider')]
    public function testTheTrustMarksClaimIsAbsentWhenThereAreNone(?array $configured): void
    {
        $this->trustMarkTokens = $configured;
        $this->dynamicTrustMarks = $configured;

        $this->assertArrayNotHasKey(ClaimsEnum::TrustMarks->value, $this->publishedPayload());
    }


    /**
     * The first configured pair is the one that signs, and the header names it so a verifier can pick it
     * out of the JWKS the same statement carries. Two pairs are configured, so this is a choice rather
     * than the only option: the second carries a different algorithm, and signing with it would show up
     * in all three of these.
     *
     * @throws \Exception
     */
    public function testTheFirstConfiguredKeyPairIsTheOneThatSigns(): void
    {
        $this->publishedPayload();

        $this->assertSame(self::KEY_ID, ($this->signedHeader ?? [])[ClaimsEnum::Kid->value] ?? null);
        $this->assertSame($this->firstPrivateKey, $this->signedWithKey);
        $this->assertSame(SignatureAlgorithmEnum::RS256, $this->signedWithAlgorithm);
    }


    /**
     * Cached under the configured duration for produced statements, and under the same keys the lookup
     * used -- a statement written where it will not be looked for is a cache which never hits.
     *
     * @throws \Exception
     */
    public function testTheProducedStatementIsCachedWhereItWillBeLookedFor(): void
    {
        $this->sut()->configuration();

        $this->assertCount(1, $this->cacheWrites);
        $this->assertSame(self::SIGNED_TOKEN, $this->cacheWrites[0]['token']);
        $this->assertEquals(new DateInterval('PT2M'), $this->cacheWrites[0]['ttl']);
        $this->assertSame($this->cacheReadKeys, $this->cacheWrites[0]['keys']);
        $this->assertContains(self::ISSUER, $this->cacheWrites[0]['keys']);
    }


    /**
     * A deployment with no federation cache configured still serves the endpoint; it just signs a
     * statement every time.
     *
     * @throws \Exception
     */
    public function testIsServedWithoutAFederationCacheAtAll(): void
    {
        // Built directly: sut() fills a null collaborator with its mock, and here the null is the point.
        $sut = new EntityStatementController(
            $this->moduleConfigMock,
            $this->jwksMock,
            $this->opMetadataServiceMock,
            $this->helpersMock,
            $this->routesMock,
            $this->federationMock,
            $this->loggerServiceMock,
            null,
        );

        $response = $sut->configuration();

        $this->assertSame(self::SIGNED_TOKEN, $response->getContent());
        $this->assertSame(1, $this->signedCount);
        $this->assertSame([], $this->cacheWrites);
    }


    /**
     * The media type is what tells a fetcher this is an entity statement rather than JSON, and the
     * permissive origin is deliberate: the statement is public by design and browser-based federation
     * tooling reads it.
     *
     * @throws \Exception
     */
    public function testIsServedAsAPublicEntityStatementJwt(): void
    {
        $response = $this->sut()->configuration();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            ContentTypesEnum::ApplicationEntityStatementJwt->value,
            $response->headers->get(HttpHeadersEnum::ContentType->value),
        );
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
    }
}
