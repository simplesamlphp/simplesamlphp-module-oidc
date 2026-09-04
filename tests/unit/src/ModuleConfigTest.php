<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use DateInterval;
use Defuse\Crypto\Key;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Database;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\OpenID\ValueAbstracts\Factories\SignatureKeyPairBagFactory;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

#[CoversClass(ModuleConfig::class)]
#[AllowMockObjectsWithoutExpectations]
class ModuleConfigTest extends TestCase
{
    protected string $fileName;

    protected array $overrides;

    protected MockObject $sspConfigMock;

    protected array $moduleConfig = [
        ModuleConfig::OPTION_ISSUER => 'http://test.issuer',

        ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
            [
                ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
                ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module_connect_rsa_01.key',
                ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module_connect_rsa_01.pub',
            ],
        ],

        ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
        ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1M',
        ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

        ModuleConfig::OPTION_CRON_TAG => 'hourly',

        ModuleConfig::OPTION_AUTH_SOURCE => 'default-sp',

        ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE => 'uid',

        ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES => [
        ],
        ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE => [
        ],

        ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED => [
        ],

        ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP => [
        ],

        ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION => null,

        ModuleConfig::OPTION_FEDERATION_AUTHORITY_HINTS => [
            'abc123',
        ],

        ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER => ArrayAdapter::class,
        ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER_ARGUMENTS => [],
        ModuleConfig::OPTION_PROTOCOL_USER_ENTITY_CACHE_DURATION => null,
        ModuleConfig::OPTION_PROTOCOL_CLIENT_ENTITY_CACHE_DURATION => null,
    ];

    private MockObject $sspBridgeMock;

    private MockObject $sspBridgeUtilsMock;

    private MockObject $sspBridgeUtilsHttpMock;

    private MockObject $sspBridgeUtilsConfigMock;

    private MockObject $valueAbstractMock;


    protected function setUp(): void
    {
        $this->fileName = ModuleConfig::DEFAULT_FILE_NAME;
        $this->sspConfigMock = $this->createMock(Configuration::class);
        $this->overrides = [];

        $this->sspBridgeMock = $this->createMock(SspBridge::class);

        $this->sspBridgeUtilsMock = $this->createMock(Utils::class);

        $this->sspBridgeUtilsConfigMock = $this->createMock(Config::class);
        $this->sspBridgeUtilsConfigMock->method('getCertPath')
            ->willReturnCallback(
                fn(string $filename): string => dirname(__DIR__, 2) . '/cert/' . $filename,
            );
        $this->sspBridgeUtilsHttpMock = $this->createMock(HTTP::class);

        $this->sspBridgeMock->method('utils')->willReturn($this->sspBridgeUtilsMock);

        $this->sspBridgeUtilsMock->method('http')->willReturn($this->sspBridgeUtilsHttpMock);
        $this->sspBridgeUtilsMock->method('config')->willReturn($this->sspBridgeUtilsConfigMock);

        $this->valueAbstractMock = $this->createMock(ValueAbstracts::class);
    }


    protected function sut(
        ?string $fileName = null,
        ?array $overrides = null,
        ?Configuration $sspConfig = null,
        ?SspBridge $sspBridge = null,
        ?ValueAbstracts $valueAbstracts = null,
    ): ModuleConfig {
        $fileName ??= $this->fileName;
        $overrides ??= $this->overrides;
        $sspConfig ??= $this->sspConfigMock;
        $sspBridge ??= $this->sspBridgeMock;
        $valueAbstracts ??= $this->valueAbstractMock;

        return new ModuleConfig(
            $fileName,
            $overrides,
            $sspConfig,
            $sspBridge,
            $valueAbstracts,
        );
    }


    public function testCanGetCommonOptions(): void
    {
        $this->assertSame(ModuleConfig::MODULE_NAME, $this->sut()->moduleName());

        $this->assertInstanceOf(DateInterval::class, $this->sut()->getAuthCodeDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getAccessTokenDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getRefreshTokenDuration());

        $this->assertInstanceOf(SupportedAlgorithms::class, $this->sut()->getSupportedAlgorithms());
        $this->assertInstanceOf(SupportedSerializers::class, $this->sut()->getSupportedSerializers());

        $this->assertSame(
            $this->moduleConfig[ModuleConfig::OPTION_AUTH_SOURCE],
            $this->sut()->getDefaultAuthSourceId(),
        );
    }


    public function testCanGetProtocolSignatureKeyPairs(): void
    {
        $this->assertNotEmpty($this->sut()->getProtocolSignatureKeyPairs());
    }


    public function testGetProtocolSignatureKeyPairsThrowsOnInvalidConfigValue(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('At least one ');

        $this->sut(
            overrides: [ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => []],
        )->getProtocolSignatureKeyPairs();
    }


    public function testCanGetProtocolSignatureKeyPairConfigBag(): void
    {
        $sut = $this->sut();

        $this->assertInstanceOf(
            SignatureKeyPairConfigBag::class,
            $sut->getProtocolSignatureKeyPairConfigBag(),
        );
        $this->assertInstanceOf(
            SignatureKeyPairConfigBag::class,
            $sut->getProtocolSignatureKeyPairConfigBag(),
        );
    }


    public function testCanGetProtocolSignatureKeyPairgBag(): void
    {
        $sut = $this->sut();

        $this->assertInstanceOf(
            SignatureKeyPairBag::class,
            $sut->getProtocolSignatureKeyPairBag(),
        );
        $this->assertInstanceOf(
            SignatureKeyPairBag::class,
            $sut->getProtocolSignatureKeyPairBag(),
        );
    }


    public function testCanGetSspConfig(): void
    {
        $this->assertInstanceOf(Configuration::class, $this->sut()->sspConfig());
    }


    public function testCanGetOpenIdScopes(): void
    {
        $this->assertNotEmpty($this->sut()->getScopes());
    }


    public function testCanGetAuthProcFilters(): void
    {
        $this->assertIsArray($this->sut()->getAuthProcFilters());
    }


    public function testCanGetIssuer(): void
    {
        $this->assertNotEmpty($this->sut()->getIssuer());
    }


    public function testGetsCurrentHostIfIssuerNotSetInConfig(): void
    {
        $this->sspBridgeUtilsHttpMock->expects($this->once())->method('getSelfURLHost')
            ->willReturn('sample');
        $this->overrides[ModuleConfig::OPTION_ISSUER] = null;
        $this->sut()->getIssuer();
    }


    public function testThrowsOnEmptyIssuer(): void
    {
        $this->overrides[ModuleConfig::OPTION_ISSUER] = '';
        $this->expectException(OidcServerException::class);

        $this->sut()->getIssuer();
    }


    public function testCanGetForcedAcrValueForCookieAuthentication(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION] = '1a';
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = ['1a'];
        $this->assertEquals('1a', $this->sut()->getForcedAcrValueForCookieAuthentication());
    }


    public function testCanGetUserIdentifierAttribute(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE] = 'sample';
        $this->assertEquals('sample', $this->sut()->getUserIdentifierAttribute());
    }


    public function testCanGetUserIdentifierAttributesFromString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE] = 'sample';
        $this->assertEquals(['sample'], $this->sut()->getUserIdentifierAttributes());
    }


    public function testCanGetUserIdentifierAttributesFromArray(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE] = ['ePPN', 'uid'];
        $this->assertEquals(['ePPN', 'uid'], $this->sut()->getUserIdentifierAttributes());
        // The deprecated single accessor returns the primary (first) candidate.
        $this->assertEquals('ePPN', $this->sut()->getUserIdentifierAttribute());
    }


    public function testCanGetCommonFederationOptions(): void
    {
        $this->assertFalse($this->sut()->getFederationEnabled());
        $this->assertNotEmpty($this->sut()->getFederationEntityStatementDuration());
        $this->assertNotEmpty($this->sut()->getFederationEntityStatementCacheDurationForProduced());
        $this->assertNotEmpty($this->sut()->getFederationAuthorityHints());
        $this->assertNotEmpty($this->sut()->getFederationTrustMarkTokens());
        $this->assertNotEmpty($this->sut()->getOrganizationName());
        $this->assertNotEmpty($this->sut()->getDisplayName());
        $this->assertNotEmpty($this->sut()->getDescription());
        $this->assertNotEmpty($this->sut()->getKeywords());
        $this->assertNotEmpty($this->sut()->getContacts());
        $this->assertNotEmpty($this->sut()->getLogoUri());
        $this->assertNotEmpty($this->sut()->getPolicyUri());
        $this->assertNotEmpty($this->sut()->getInformationUri());
        $this->assertNotEmpty($this->sut()->getOrganizationUri());
        $this->assertNotEmpty($this->sut()->getFederationCacheAdapterClass());
        $this->assertIsArray($this->sut()->getFederationCacheAdapterArguments());
        $this->assertNotEmpty($this->sut()->getFederationCacheMaxDurationForFetched());
        $this->assertNotEmpty($this->sut()->getFederationTrustAnchors());
        $this->assertNotEmpty($this->sut()->getFederationTrustAnchorIds());

        $this->assertInstanceOf(DateInterval::class, $this->sut()->getTimestampValidationLeeway());
    }


    /**
     * The defaults deliberately mirror the `openid` library's own, so that the module does not silently
     * diverge from the limits upstream calibrated.
     */
    public function testFederationTraversalLimitsDefaultToLibraryValues(): void
    {
        $sut = $this->sut();

        $this->assertSame(9, $sut->getFederationMaxTrustChainDepth());
        $this->assertSame(6, $sut->getFederationMaxAuthorityHints());
        $this->assertSame(100, $sut->getFederationMaxTrustChainFetches());
        $this->assertSame(30, $sut->getFederationTrustChainResolveTimeout());
        $this->assertSame(102400, $sut->getFederationMaxFetchSizeBytes());
        $this->assertSame([], $sut->getFederationHttpClientOptions());
    }


    public function testCanOverrideFederationTraversalLimits(): void
    {
        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_DEPTH => 3,
                ModuleConfig::OPTION_FEDERATION_MAX_AUTHORITY_HINTS => 2,
                ModuleConfig::OPTION_FEDERATION_MAX_TRUST_CHAIN_FETCHES => 25,
                ModuleConfig::OPTION_FEDERATION_TRUST_CHAIN_RESOLVE_TIMEOUT => 10,
                ModuleConfig::OPTION_FEDERATION_MAX_FETCH_SIZE_BYTES => 4096,
            ],
        );

        $this->assertSame(3, $sut->getFederationMaxTrustChainDepth());
        $this->assertSame(2, $sut->getFederationMaxAuthorityHints());
        $this->assertSame(25, $sut->getFederationMaxTrustChainFetches());
        $this->assertSame(10, $sut->getFederationTrustChainResolveTimeout());
        $this->assertSame(4096, $sut->getFederationMaxFetchSizeBytes());
    }


    /**
     * Federation HTTP client options are read independently of the protocol-layer ones, so that disabling TLS
     * verification for one can never leak into the other.
     */
    public function testFederationHttpClientOptionsAreSeparateFromProtocolOnes(): void
    {
        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_HTTP_CLIENT_OPTIONS => ['verify' => false, 'timeout' => 7],
            ],
        );

        $this->assertSame(['verify' => false, 'timeout' => 7], $sut->getFederationHttpClientOptions());
        $this->assertSame([], $sut->getProtocolHttpClientOptions());
    }


    public function testCanGetFederationSignatureKeyPairBag(): void
    {
        $sut = $this->sut();
        $this->assertInstanceOf(SignatureKeyPairBag::class, $sut->getFederationSignatureKeyPairBag());
        $this->assertInstanceOf(SignatureKeyPairBag::class, $sut->getFederationSignatureKeyPairBag());
    }


    public function testGetFederationSignatureKeyPairBagThrowsOnInvalidConfigValue(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('At least one ');

        $this->sut(
            overrides: [ModuleConfig::OPTION_FEDERATION_SIGNATURE_KEY_PAIRS => []],
        )->getFederationSignatureKeyPairBag();
    }


    /**
     * The whole of the Verifiable Credential Issuance rollover model: additional pairs are published
     * so they can verify, and the one listed first is the one that signs. Everything which signs asks
     * this method, so this is the single place that decision is made.
     */
    public function testActiveVciSignatureKeyPairIsTheFirstConfiguredOne(): void
    {
        $sut = $this->sutWithVciSignatureKeyPairBag(
            new SignatureKeyPairBag(
                $this->buildSignatureKeyPair('vci-01', SignatureAlgorithmEnum::ES256),
                $this->buildSignatureKeyPair('vci-02', SignatureAlgorithmEnum::RS256),
            ),
        );

        $activeSignatureKeyPair = $sut->getActiveVciSignatureKeyPair();

        $this->assertSame('vci-01', $activeSignatureKeyPair->getKeyPair()->getKeyId());
        $this->assertSame(SignatureAlgorithmEnum::ES256, $activeSignatureKeyPair->getSignatureAlgorithm());
    }


    public function testGetActiveVciSignatureKeyPairThrowsWhenNoKeyPairCouldBeBuilt(): void
    {
        $sut = $this->sutWithVciSignatureKeyPairBag(new SignatureKeyPairBag());

        $this->expectException(OpenIdException::class);

        $sut->getActiveVciSignatureKeyPair();
    }


    /**
     * A ModuleConfig whose VCI option resolves to the given bag, so that a test can decide what the
     * bag holds without needing a key pair per algorithm on disk.
     */
    protected function sutWithVciSignatureKeyPairBag(SignatureKeyPairBag $signatureKeyPairBag): ModuleConfig
    {
        $signatureKeyPairBagFactoryMock = $this->createMock(SignatureKeyPairBagFactory::class);
        $signatureKeyPairBagFactoryMock->method('fromConfig')->willReturn($signatureKeyPairBag);

        $valueAbstractsMock = $this->createMock(ValueAbstracts::class);
        $valueAbstractsMock->method('signatureKeyPairBagFactory')->willReturn($signatureKeyPairBagFactoryMock);

        return $this->sut(
            overrides: [
                ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS => [
                    [
                        ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
                        ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
                        ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module.crt',
                    ],
                ],
            ],
            valueAbstracts: $valueAbstractsMock,
        );
    }


    protected function buildSignatureKeyPair(string $keyId, SignatureAlgorithmEnum $algorithm): SignatureKeyPair
    {
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getKeyId')->willReturn($keyId);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn($algorithm);

        return $signatureKeyPairMock;
    }


    public function testKeywordsCanBeNull(): void
    {
        $this->assertNull(
            $this->sut(
                overrides: [
                    ModuleConfig::OPTION_KEYWORDS => null,
                ],
            )->getKeywords(),
        );
    }


    public function testGetFederationTrustAnchorsThrowsOnEmptyIfFederationEnabled(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('No Trust Anchors');

        $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_ENABLED => true,
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => [],
            ],
        )->getFederationTrustAnchors();
    }


    public function testCanGetTrustAnchorJwksJson(): void
    {
        $this->assertNotEmpty($this->sut()->getTrustAnchorJwksJson('https://ta.example.org/'));
        $this->assertEmpty($this->sut()->getTrustAnchorJwksJson('invalid'));
    }


    public function testGetTrustAnchorJwksJsonThrowsOnInvalidData(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('format');

        $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_TRUST_ANCHORS => ['ta' => 123],
            ],
        )->getTrustAnchorJwksJson('ta');
    }


    public function testThrowsIfTryingToOverrideProtectedScopes(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES] = [
            'openid' => [
                'description' => 'openid',
            ],
        ];

        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfCustomScopeDoesNotHaveDescription(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES] = [
            'custom' => [],
        ];

        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfAcrIsNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = [123];

        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfAuthSourceNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = [123 => []];
        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfAuthSourceToAcrMapAcrNotArray(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => 123];
        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfAuthSourceToAcrMapAcrNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => [123]];
        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIfAuthSourceToAcrMapAcrNotAllowed(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => ['acr']];
        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testThrowsIForcedAcrValueForCookieAuthenticationNotAllowed(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = ['abc'];
        $this->overrides[ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION] = 'cba';
        $this->expectException(ConfigurationError::class);
        $this->sut();
    }


    public function testCanGetEncryptionKey(): void
    {
        $this->sspBridgeUtilsConfigMock->expects($this->once())->method('getSecretSalt')
        ->willReturn('secretSalt');

        $this->assertSame('secretSalt', $this->sut()->getEncryptionKey());
    }


    public function testCanGetEncryptionKeyAsDefuseKey(): void
    {
        $this->sspBridgeUtilsConfigMock->expects($this->never())->method('getSecretSalt');

        $key = Key::createNewRandomKey();
        $this->overrides[ModuleConfig::OPTION_ENCRYPTION_KEY] = $key->saveToAsciiSafeString();

        $encryptionKey = $this->sut()->getEncryptionKey();

        $this->assertInstanceOf(Key::class, $encryptionKey);
        $this->assertSame($key->saveToAsciiSafeString(), $encryptionKey->saveToAsciiSafeString());
    }


    public function testGetEncryptionKeyThrowsForInvalidDefuseKey(): void
    {
        $this->overrides[ModuleConfig::OPTION_ENCRYPTION_KEY] = 'not-a-valid-ascii-safe-key';

        $this->expectException(ConfigurationError::class);

        $this->sut()->getEncryptionKey();
    }


    public function testCanGetProtocolCacheConfiguration(): void
    {
        $this->assertNotEmpty($this->sut()->getProtocolCacheAdapterClass());
        $this->assertIsArray($this->sut()->getProtocolCacheAdapterArguments());

        $this->assertInstanceOf(DateInterval::class, $this->sut()->getProtocolUserEntityCacheDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getProtocolClientEntityCacheDuration());
    }


    public function testCanGetRequestUriParameterSupported(): void
    {
        // Default.
        $this->assertTrue($this->sut()->getRequestUriParameterSupported());

        $this->assertFalse(
            $this->sut(
                overrides: [ModuleConfig::OPTION_REQUEST_URI_PARAMETER_SUPPORTED => false],
            )->getRequestUriParameterSupported(),
        );
    }


    public function testGetFederationRequestUriAllowedPrefixesDeniesByDefault(): void
    {
        // Option absent -> deny all federation-candidate fetches (empty allowlist).
        $this->assertSame([], $this->sut()->getFederationRequestUriAllowedPrefixes());
    }


    public function testGetFederationRequestUriAllowedPrefixesCanAllowAny(): void
    {
        // Explicit null -> allow any.
        $this->assertNull(
            $this->sut(
                overrides: [ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => null],
            )->getFederationRequestUriAllowedPrefixes(),
        );
    }


    public function testGetFederationRequestUriAllowedPrefixesReturnsConfiguredPrefixes(): void
    {
        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES => [
                    'https://rp.example.org/',
                    123, // non-string values are filtered out
                ],
            ],
        );

        $this->assertSame(['https://rp.example.org/'], $sut->getFederationRequestUriAllowedPrefixes());
    }


    public function testCanGetProtocolDiscoveryShowClaimsSupported(): void
    {
        $this->assertFalse($this->sut()->getProtocolDiscoveryShowClaimsSupported());
        $this->assertTrue(
            $this->sut(
                overrides: [ModuleConfig::OPTION_PROTOCOL_DISCOVERY_SHOW_CLAIMS_SUPPORTED => true],
            )->getProtocolDiscoveryShowClaimsSupported(),
        );
    }


    public function testCanGetFederationDynamicTrustMarks(): void
    {
        $this->assertNull($this->sut()->getFederationDynamicTrustMarks());

        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_DYNAMIC_TRUST_MARKS => [
                    'trust-mark-type' => 'trust-mark-issuer-id',
                ],
            ],
        );

        $this->assertArrayHasKey(
            'trust-mark-type',
            $sut->getFederationDynamicTrustMarks(),
        );
    }


    public function testCanGetFederationParticipationLimitByTrustMarks(): void
    {
        $this->assertArrayHasKey(
            'https://ta.example.org/',
            $this->sut()->getFederationParticipationLimitByTrustMarks(),
        );
    }


    public function testCanGetTrustMarksNeededForFederationParticipationFor(): void
    {
        $neededTrustMarks = $this->sut()->getTrustMarksNeededForFederationParticipationFor('https://ta.example.org/');

        $this->assertArrayHasKey('one_of', $neededTrustMarks);
        $this->assertTrue(in_array('trust-mark-type', $neededTrustMarks['one_of']));
    }


    public function testGetTrustMarksNeededForFederationParticipationForThrowsOnInvalidConfigValue(): void
    {
        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_PARTICIPATION_LIMIT_BY_TRUST_MARKS => [
                    'https://ta.example.org/' => 'invalid',
                ],
            ],
        );

        $this->expectException(ConfigurationError::class);

        $sut->getTrustMarksNeededForFederationParticipationFor('https://ta.example.org/');
    }


    public function testCanGetIsFederationParticipationLimitedByTrustMarksFor(): void
    {
        $this->assertTrue(
            $this->sut()->isFederationParticipationLimitedByTrustMarksFor('https://ta.example.org/'),
        );
    }


    public function testCanGetFederationTrustMarkStatusEndpointUsagePolicy(): void
    {
        // Assert default policy.
        $this->assertSame(
            TrustMarkStatusEndpointUsagePolicyEnum::RequiredIfEndpointProvidedForNonExpiringTrustMarksOnly,
            $this->sut()->getFederationTrustMarkStatusEndpointUsagePolicy(),
        );

        // Assert custom configuration.
        $sut = $this->sut(
            overrides: [
                ModuleConfig::OPTION_FEDERATION_TRUST_MARK_STATUS_ENDPOINT_USAGE_POLICY =>
                    TrustMarkStatusEndpointUsagePolicyEnum::Required,
            ],
        );
        $this->assertSame(
            TrustMarkStatusEndpointUsagePolicyEnum::Required,
            $sut->getFederationTrustMarkStatusEndpointUsagePolicy(),
        );
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnInvalidValue(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Invalid value');

        $this->sut()->getValidatedSignatureKeyPairArray('invalid');
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnInvalidSignature(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => 'invalid',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Invalid protocol signature algorithm');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnInvalidPrivateKey(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => '',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Unexpected value for private key filename');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnNonExistingPrivateKey(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'non-existing.key',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Private key file does not exist');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnInvalidPublicKey(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => '',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Unexpected value for public key filename');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnNonExistingPublicKey(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'non-existing.pub',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Public key file does not exist');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnEmptyPasswordString(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module.crt',
            ModuleConfig::KEY_PRIVATE_KEY_PASSWORD => '',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Expected a non-empty string');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }


    public function testGetValidatedSignatureKeyPairArrayThrowsOnEmptyKeyIdString(): void
    {
        $value = [
            ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
            ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
            ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module.crt',
            ModuleConfig::KEY_PRIVATE_KEY_PASSWORD => 'password',
            ModuleConfig::KEY_KEY_ID => '',
        ];

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('Expected a non-empty string');

        $this->sut()->getValidatedSignatureKeyPairArray($value);
    }

    /*****************************************************************************************************************
     * Token Status List
     ****************************************************************************************************************/

    /**
     * Off unless a deployment opts in, since it changes what is stored about issued credentials.
     *
     * @throws \Exception
     */
    public function testStatusListsAreDisabledByDefault(): void
    {
        $this->assertFalse($this->sut()->getVciStatusListEnabled());
    }


    /**
     * @throws \Exception
     */
    public function testStatusListsCanBeEnabled(): void
    {
        $this->assertTrue(
            $this->sut(overrides: [ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true])
                ->getVciStatusListEnabled(),
        );
    }


    /**
     * SimpleSAMLphp is a development dependency here, so nothing stops this module being installed into
     * a host which lacks the primary read. Deciding whether a credential has been revoked off a lagging
     * secondary can publish a revoked credential as valid, so the capability is required rather than
     * degraded to a replica read.
     */
    public function testPrimaryDatabaseReadCapabilityIsDetectedRatherThanAssumed(): void
    {
        $this->assertSame(
            method_exists(Database::class, ModuleConfig::SSP_PRIMARY_READ_METHOD),
            ModuleConfig::hasPrimaryDatabaseReadCapability(),
        );

        // The installed SimpleSAMLphp must provide it, otherwise the capability could never be enabled.
        $this->assertTrue(ModuleConfig::hasPrimaryDatabaseReadCapability());
    }


    /**
     * @throws \Exception
     */
    public function testStatusListKeyProfileDefaultsToDidJwk(): void
    {
        $this->assertSame(
            StatusListKeyProfileEnum::DidJwk,
            $this->sut()->getVciStatusListKeyProfile(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testStatusListKeyProfileAcceptsAnEnumCaseOrItsValue(): void
    {
        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $this->sut(overrides: [
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::Jwks,
            ])->getVciStatusListKeyProfile(),
        );

        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $this->sut(overrides: [ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => 'jwks'])
                ->getVciStatusListKeyProfile(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testStatusListKeyProfileRejectsAnUnknownValue(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: [ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => 'x509'])
            ->getVciStatusListKeyProfile();
    }


    /**
     * A typo here would otherwise be silent: the pool would never be allocated from, and the
     * credentials which were meant to be revocable would be issued without a status claim.
     *
     * @throws \Exception
     */
    public function testStatusListPoolsRejectAnUnknownCredentialConfiguration(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('NoSuchCredential');

        $this->sut(overrides: [
            ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                'default' => [
                    StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['NoSuchCredential'],
                ],
            ],
        ])->getVciStatusListPoolBag();
    }


    /**
     * @throws \Exception
     */
    public function testResolvesTheStatusListPoolForACredentialConfiguration(): void
    {
        $sut = $this->sut(overrides: $this->withStatusListPool(true));

        $this->assertSame('default', $sut->getVciStatusListPoolFor('TestCredential')?->getId());

        // A configuration in no pool is not an error: its credentials are issued without a status
        // claim, and so can not be revoked.
        $this->assertNull($sut->getVciStatusListPoolFor('SomethingElse'));
    }


    /**
     * With the capability off, nothing allocates, so no credential configuration resolves to a pool
     * even when one is configured.
     *
     * @throws \Exception
     */
    public function testResolvesNoStatusListPoolWhileTheCapabilityIsDisabled(): void
    {
        $sut = $this->sut(overrides: $this->withStatusListPool(false));

        $this->assertNull($sut->getVciStatusListPoolFor('TestCredential'));

        // The pool itself is still readable, so the administration screens can show what is configured
        // even while it is inert.
        $this->assertSame('default', $sut->getVciStatusListPoolBag()->getById('default')?->getId());
    }


    /**
     * @return array<string,mixed>
     */
    protected function withStatusListPool(bool $isEnabled): array
    {
        return array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'TestCredential' => [],
                ],
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => $isEnabled,
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                    'default' => [
                        StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['TestCredential'],
                    ],
                ],
            ],
        );
    }


    /**
     * The did:web key profile names the issuer by an identifier the pool does not carry itself, so the
     * module wide one is handed to it. A deployment has one such identity, and a pool naming a second
     * would leave one of them without the DID document a Relying Party has to resolve.
     *
     * @throws \Exception
     */
    public function testHandsTheIssuerIdentifierToAPoolOnTheDidWebKeyProfile(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb,
                ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:issuer.example.org',
            ],
        ));

        $pool = $sut->getVciStatusListPoolBag()->getById('default');

        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $pool?->getKeyProfile());
        $this->assertSame('did:web:issuer.example.org', $pool->getIssuerIdentifier());
    }


    /**
     * Answered without building the pools, so that a pool which cannot be built -- here a `did_web` one
     * whose issuer identifier is missing -- cannot change the answer for one which can. The JWKS
     * endpoint decides whether to keep publishing the credential signing key by asking this, and a
     * `jwks` pool's already published tokens are verified through that key.
     *
     * @throws \Exception
     */
    public function testAnswersWhichKeyProfilesAreInUseEvenWhileAnotherPoolCanNotBeBuilt(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'TestCredential' => [],
                    'OtherCredential' => [],
                ],
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                    'published' => [
                        StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['TestCredential'],
                        StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::Jwks,
                    ],
                    // No issuer did:web is configured, so building this one throws.
                    'decentralised' => [
                        StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['OtherCredential'],
                        StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb,
                    ],
                ],
            ],
        ));

        $this->assertTrue($sut->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::Jwks));
        $this->assertTrue($sut->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::DidWeb));
        $this->assertFalse($sut->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::DidJwk));

        // The pool bag itself is still refused, which is where that error belongs.
        $this->expectException(ConfigurationError::class);

        $sut->getVciStatusListPoolBag();
    }


    /**
     * A pool which names no profile of its own takes the deployment default, so the answer has to
     * follow that rather than only what each pool spells out.
     *
     * @throws \Exception
     */
    public function testAPoolWhichNamesNoKeyProfileCountsUnderTheDeploymentDefault(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::Jwks],
        ));

        $this->assertTrue($sut->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::Jwks));
        $this->assertFalse($sut->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::DidJwk));
    }


    /**
     * @throws \Exception
     */
    public function testNoPoolIsOnAnyKeyProfileWhenNonePoolIsConfigured(): void
    {
        $this->assertFalse(
            $this->sut()->isAnyStatusListPoolOnKeyProfile(StatusListKeyProfileEnum::Jwks),
        );
    }


    /**
     * A pool may take the profile on its own while the deployment default is another, so whether the
     * issuer identifier is needed cannot be answered from the default alone. Spelled as the string a
     * hand written config would use, which is the other shape that has to be recognised.
     *
     * @throws \Exception
     */
    public function testHandsTheIssuerIdentifierToAPoolWhichTakesTheDidWebProfileOnItsOwn(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::DidJwk,
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                    'default' => [
                        StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => ['TestCredential'],
                        StatusListPool::KEY_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb->value,
                    ],
                ],
                ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:issuer.example.org',
            ],
        ));

        $pool = $sut->getVciStatusListPoolBag()->getById('default');

        $this->assertSame(StatusListKeyProfileEnum::DidWeb, $pool?->getKeyProfile());
        $this->assertSame('did:web:issuer.example.org', $pool->getIssuerIdentifier());
    }


    /**
     * @throws \Exception
     */
    public function testRefusesAPoolOnTheDidWebKeyProfileWithNoIssuerIdentifier(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER);

        $sut->getVciStatusListPoolBag();
    }


    /**
     * A pool on a profile which never looks at the issuer did:web must stay readable when that option
     * is malformed. The JWKS endpoint decides whether to publish the credential signing key by reading
     * the pools, so a failure here would withdraw the key that a `jwks` profile pool's already
     * published tokens are verified through -- over a setting those tokens do not use.
     *
     * @throws \Exception
     */
    public function testAMalformedIssuerIdentifierDoesNotStopPoolsWhichDoNotUseOneFromResolving(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::Jwks,
                ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:localhost',
            ],
        ));

        $this->assertSame(
            StatusListKeyProfileEnum::Jwks,
            $sut->getVciStatusListPoolBag()->getById('default')?->getKeyProfile(),
        );
    }


    /**
     * The same option is still refused where it is actually used, so a malformed identifier cannot
     * reach a list which would then be signed under it.
     *
     * @throws \Exception
     */
    public function testAMalformedIssuerIdentifierIsStillRefusedForAPoolWhichUsesOne(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [
                ModuleConfig::OPTION_VCI_STATUS_LIST_KEY_PROFILE => StatusListKeyProfileEnum::DidWeb,
                ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:localhost',
            ],
        ));

        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER);

        $sut->getVciStatusListPoolBag();
    }


    /**
     * A pool whose credential configurations all lack a lifetime allocates only into the non-expiring
     * lane, so any list it has in the other one is no longer an allocation target and has to be
     * deactivated -- otherwise nothing would ever fill it, nothing would deactivate it, and it would be
     * served for ever without being retired.
     *
     * @throws \Exception
     */
    public function testResolvesOnlyTheNonExpiringLaneForAPoolWithoutLifetimes(): void
    {
        $sut = $this->sut(overrides: $this->withStatusListPool(true));
        $pool = $sut->getVciStatusListPoolBag()->getById('default');

        $this->assertNotNull($pool);
        $this->assertSame(
            [StatusListExpiryLaneEnum::NonExpiring],
            $sut->getVciStatusListCurrentLanesFor($pool),
        );
    }


    /**
     * @throws \Exception
     */
    public function testResolvesOnlyTheExpiringLaneWhenEveryConfigurationHasALifetime(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->withStatusListPool(true),
            [ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => ['TestCredential' => 'P1Y']],
        ));
        $pool = $sut->getVciStatusListPoolBag()->getById('default');

        $this->assertNotNull($pool);
        $this->assertSame([StatusListExpiryLaneEnum::Expiring], $sut->getVciStatusListCurrentLanesFor($pool));
    }


    /**
     * A mixed pool keeps a list in each lane, and both are current. Reporting only one would have the
     * lifecycle deactivate the other on every run, and the allocator recreate it on the next allocation.
     *
     * @throws \Exception
     */
    public function testResolvesBothLanesForAPoolWhoseConfigurationsDiffer(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => [
                    'TestCredential' => [],
                    'PermanentCredential' => [],
                ],
                ModuleConfig::OPTION_VCI_STATUS_LIST_ENABLED => true,
                ModuleConfig::OPTION_VCI_STATUS_LIST_POOLS => [
                    'default' => [
                        StatusListPool::KEY_CREDENTIAL_CONFIGURATIONS => [
                            'TestCredential',
                            'PermanentCredential',
                        ],
                    ],
                ],
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => ['TestCredential' => 'P1Y'],
            ],
        ));
        $pool = $sut->getVciStatusListPoolBag()->getById('default');

        $this->assertNotNull($pool);

        $lanes = $sut->getVciStatusListCurrentLanesFor($pool);

        $this->assertCount(2, $lanes);
        $this->assertContains(StatusListExpiryLaneEnum::Expiring, $lanes);
        $this->assertContains(StatusListExpiryLaneEnum::NonExpiring, $lanes);
    }


    /**
     * Not expiring is what this module has always done, and an expiry changes what already issued
     * credentials mean, so it stays something an operator asks for.
     *
     * @throws \Exception
     */
    public function testCredentialsHaveNoLifetimeUnlessOneIsConfigured(): void
    {
        $sut = $this->sut();

        $this->assertSame([], $sut->getVciCredentialTtls());
        $this->assertNull($sut->getVciCredentialTtlFor('TestCredential'));
    }


    /**
     * @throws \Exception
     */
    public function testResolvesTheConfiguredCredentialLifetime(): void
    {
        $sut = $this->sut(overrides: $this->withCredentialTtl('P30D'));

        $this->assertSame(30, $sut->getVciCredentialTtlFor('TestCredential')?->d);
        // Configurations which are not listed keep issuing credentials which never expire.
        $this->assertNull($sut->getVciCredentialTtlFor('SomethingElse'));
    }


    /**
     * As with the pools, a typo would otherwise be silent: credentials which were meant to expire
     * would go on being issued without an expiry and nothing would say so.
     *
     * @throws \Exception
     */
    public function testCredentialLifetimesRejectAnUnknownCredentialConfiguration(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('NoSuchCredential');

        $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => ['NoSuchCredential' => 'P30D'],
            ],
        ))->getVciCredentialTtls();
    }


    /**
     * @throws \Exception
     */
    public function testCredentialLifetimesRejectAnUnparseableDuration(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withCredentialTtl('thirty days'))->getVciCredentialTtls();
    }


    /**
     * A zero lifetime would issue credentials which have already expired, which is never what was
     * meant. Leaving the entry out is how a configuration says its credentials do not expire.
     *
     * @throws \Exception
     */
    public function testCredentialLifetimesRejectADurationOfNoTime(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withCredentialTtl('PT0S'))->getVciCredentialTtls();
    }


    /**
     * The metadata this module publishes has always said a key proof is required, so requiring one is
     * what an unlisted configuration keeps doing. Issuing credentials which are bound to nothing is the
     * thing an operator opts into.
     *
     * @throws \Exception
     */
    public function testCredentialsAreBoundToAHolderKeyUnlessConfiguredOtherwise(): void
    {
        $sut = $this->sut();

        $this->assertSame([], $sut->getVciCredentialBindingPolicies());
        $this->assertSame(
            VciCredentialBindingPolicyEnum::ProofBound,
            $sut->getVciCredentialBindingPolicyFor('TestCredential'),
        );
    }


    /**
     * @throws \Exception
     */
    public function testResolvesTheConfiguredCredentialBindingPolicy(): void
    {
        // Both the enum and its backing value, since the configuration file is PHP and an operator may
        // reasonably write either.
        foreach ([VciCredentialBindingPolicyEnum::Proofless, 'proofless'] as $configured) {
            $sut = $this->sut(overrides: $this->withCredentialBindingPolicy($configured));

            $this->assertSame(
                VciCredentialBindingPolicyEnum::Proofless,
                $sut->getVciCredentialBindingPolicyFor('TestCredential'),
            );
            // Configurations which are not listed keep requiring a key proof.
            $this->assertSame(
                VciCredentialBindingPolicyEnum::ProofBound,
                $sut->getVciCredentialBindingPolicyFor('SomethingElse'),
            );
        }
    }


    /**
     * A typo would otherwise be silent, and the configuration it was meant for would go on demanding
     * key proofs the wallet was never going to send.
     *
     * @throws \Exception
     */
    public function testCredentialBindingPoliciesRejectAnUnknownCredentialConfiguration(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('NoSuchCredential');

        $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
                ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES => ['NoSuchCredential' => 'proofless'],
            ],
        ))->getVciCredentialBindingPolicies();
    }


    /**
     * @throws \Exception
     */
    public function testCredentialBindingPoliciesRejectAnUnknownPolicy(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withCredentialBindingPolicy('sometimes'))
            ->getVciCredentialBindingPolicies();
    }


    /**
     * The shape this option has always had, which has to go on working.
     *
     * @throws \Exception
     */
    public function testReadsApiTokenScopesGivenAsABareList(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [ModuleConfig::OPTION_API_TOKENS => ['a-token' => [ApiScopesEnum::VciAll]]],
        ));

        $this->assertSame([ApiScopesEnum::VciAll], $sut->getApiTokenScopes('a-token'));
        $this->assertNull($sut->getApiTokenName('a-token'));
    }


    /**
     * A bare list is read by value rather than by key, so one which happens to carry an entry under
     * a key of 'scopes' or 'name' authorized before this option grew a second shape. Quietly ceasing
     * to would be an authorization change nobody asked for.
     *
     * @throws \Exception
     */
    public function testStillReadsABareListWhoseKeysLookLikeSettings(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [
                        ModuleConfig::KEY_API_TOKEN_SCOPES => ApiScopesEnum::VciAll,
                        ModuleConfig::KEY_API_TOKEN_NAME => ApiScopesEnum::All,
                    ],
                ],
            ],
        ));

        $this->assertSame(
            [
                ModuleConfig::KEY_API_TOKEN_SCOPES => ApiScopesEnum::VciAll,
                ModuleConfig::KEY_API_TOKEN_NAME => ApiScopesEnum::All,
            ],
            $sut->getApiTokenScopes('a-token'),
        );
    }


    /**
     * @throws \Exception
     */
    public function testReadsApiTokenScopesAndNameGivenAsSettings(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [
                        ModuleConfig::KEY_API_TOKEN_NAME => '  HR system  ',
                        ModuleConfig::KEY_API_TOKEN_SCOPES => [ApiScopesEnum::VciCredentialStatus],
                    ],
                ],
            ],
        ));

        $this->assertSame([ApiScopesEnum::VciCredentialStatus], $sut->getApiTokenScopes('a-token'));
        $this->assertSame('HR system', $sut->getApiTokenName('a-token'));
    }


    /**
     * A token someone had already annotated with a name, listing its scopes positionally, authorized
     * before this option grew a second shape. Ceasing to would take its access away on upgrade, and
     * the name must not become a scope of its own in the process.
     *
     * @throws \Exception
     */
    public function testReadsApiTokenScopesListedAlongsideAName(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [
                        ModuleConfig::KEY_API_TOKEN_NAME => 'legacy label',
                        ApiScopesEnum::VciAll,
                    ],
                ],
            ],
        ));

        $this->assertSame([ApiScopesEnum::VciAll], array_values((array)$sut->getApiTokenScopes('a-token')));
        $this->assertNotContains('legacy label', (array)$sut->getApiTokenScopes('a-token'));
        $this->assertSame('legacy label', $sut->getApiTokenName('a-token'));
    }


    /**
     * A name on its own authorizes nothing. Reading the settings shape as though the whole array were
     * a list of scopes would hand the token a scope named after its own name.
     *
     * @throws \Exception
     */
    public function testReadsNoApiTokenScopesFromSettingsWhichDeclareNone(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [ModuleConfig::KEY_API_TOKEN_NAME => 'HR system'],
                ],
            ],
        ));

        $this->assertNull($sut->getApiTokenScopes('a-token'));
        $this->assertSame('HR system', $sut->getApiTokenName('a-token'));
    }


    /**
     * The name goes into a fixed width column in the audit trail. Left unchecked, an over-long one
     * would make every status change that token asks for fail at the point of recording it, on the
     * databases which enforce the width, and truncating it could quietly merge two principals.
     *
     * @throws \Exception
     */
    public function testRejectsAnApiTokenNameTooLongToRecord(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [
                        ModuleConfig::KEY_API_TOKEN_NAME => str_repeat(
                            'a',
                            ModuleConfig::MAX_API_TOKEN_NAME_LENGTH + 1,
                        ),
                        ModuleConfig::KEY_API_TOKEN_SCOPES => [ApiScopesEnum::All],
                    ],
                ],
            ],
        ));

        $this->expectException(ConfigurationError::class);

        $sut->getApiTokenName('a-token');
    }


    /**
     * @throws \Exception
     */
    public function testAcceptsAnApiTokenNameOfTheGreatestRecordableLength(): void
    {
        $name = str_repeat('a', ModuleConfig::MAX_API_TOKEN_NAME_LENGTH);

        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_TOKENS => [
                    'a-token' => [ModuleConfig::KEY_API_TOKEN_NAME => $name],
                ],
            ],
        ));

        $this->assertSame($name, $sut->getApiTokenName('a-token'));
    }


    /**
     * @throws \Exception
     */
    public function testReadsNothingForAnUnknownApiToken(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [ModuleConfig::OPTION_API_TOKENS => ['a-token' => [ApiScopesEnum::All]]],
        ));

        $this->assertNull($sut->getApiTokenScopes('some-other-token'));
        $this->assertNull($sut->getApiTokenName('some-other-token'));
    }


    /**
     * Nobody is a resource server until a deployment says so, since being one means being told about
     * other clients' tokens.
     *
     * @throws \Exception
     */
    public function testReadsNoIntrospectionResourceServersByDefault(): void
    {
        $this->assertSame([], $this->sut()->getApiOAuth2TokenIntrospectionResourceServerClientIds());
    }


    /**
     * @throws \Exception
     */
    public function testReadsConfiguredIntrospectionResourceServers(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS => [
                    'resource-server-one',
                    'resource-server-two',
                ],
            ],
        ));

        $this->assertSame(
            ['resource-server-one', 'resource-server-two'],
            $sut->getApiOAuth2TokenIntrospectionResourceServerClientIds(),
        );
    }


    /**
     * An entry which is not a client identifier can not name a client, and an empty one would sit in
     * the list looking like it named something. Neither is allowed to authorize anything.
     *
     * @throws \Exception
     */
    public function testDropsIntrospectionResourceServerEntriesWhichCanNotNameAClient(): void
    {
        $sut = $this->sut(overrides: array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_RESOURCE_SERVER_CLIENT_IDS => [
                    'resource-server',
                    '',
                    123,
                    null,
                    ['nested'],
                ],
            ],
        ));

        $this->assertSame(['resource-server'], $sut->getApiOAuth2TokenIntrospectionResourceServerClientIds());
    }


    /**
     * @return array<string,mixed>
     */
    protected function withCredentialTtl(mixed $ttl): array
    {
        return array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
                ModuleConfig::OPTION_VCI_CREDENTIAL_TTLS => ['TestCredential' => $ttl],
            ],
        );
    }


    /**
     * @return array<string,mixed>
     */
    protected function withCredentialBindingPolicy(mixed $bindingPolicy): array
    {
        return array_merge(
            $this->overrides,
            [
                ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED => ['TestCredential' => []],
                ModuleConfig::OPTION_VCI_CREDENTIAL_BINDING_POLICIES => ['TestCredential' => $bindingPolicy],
            ],
        );
    }


    /**
     * @return array<string,mixed>
     */
    protected function withOption(string $option, mixed $value): array
    {
        return array_merge($this->overrides, [$option => $value]);
    }


    /**
     * @throws \Exception
     */
    public function testRetirementGraceDefaultsToAMonth(): void
    {
        $this->assertSame(30, $this->sut()->getVciStatusListRetirementGrace()->d);
    }


    /**
     * @throws \Exception
     */
    public function testReadsTheConfiguredRetirementGrace(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            'P90D',
        ));

        $this->assertSame(90, $sut->getVciStatusListRetirementGrace()->d);
    }


    /**
     * The first of the two waits has to outlast an issuance which was already under way when the list
     * stopped accepting allocations, and nothing available can serialise the two instead. A wait shorter
     * than a request can take is not a wait, so there is a floor rather than only a ban on zero.
     *
     * @throws \Exception
     */
    public function testRejectsARetirementGraceOfNoTime(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            'PT0S',
        ))->getVciStatusListRetirementGrace();
    }


    /**
     * @throws \Exception
     */
    public function testRejectsARetirementGraceShorterThanAnHour(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('at least one hour');

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            'PT30M',
        ))->getVciStatusListRetirementGrace();
    }


    /**
     * @throws \Exception
     */
    public function testAcceptsTheShortestRetirementGraceThereIs(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            'PT1H',
        ));

        $this->assertSame(1, $sut->getVciStatusListRetirementGrace()->h);
    }


    /**
     * @throws \Exception
     */
    public function testRejectsAnUnparseableRetirementGrace(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            'thirty days',
        ))->getVciStatusListRetirementGrace();
    }


    /**
     * The configuration file is PHP, so a duration can arrive as an object rather than a string. That
     * has to be checked like any other value: an interval can be inverted, which no duration string can
     * express, and a negative grace subtracted from now gives a cut-off in the future -- retiring lists
     * whose credentials are still live.
     *
     * @throws \Exception
     */
    public function testRejectsAnInvertedRetirementGraceGivenAsAnInterval(): void
    {
        $inverted = new DateInterval('P30D');
        $inverted->invert = 1;

        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            $inverted,
        ))->getVciStatusListRetirementGrace();
    }


    /**
     * @throws \Exception
     */
    public function testAcceptsARetirementGraceGivenAsAnInterval(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_RETIREMENT_GRACE,
            new DateInterval('P14D'),
        ));

        $this->assertSame(14, $sut->getVciStatusListRetirementGrace()->d);
    }


    /**
     * How long a record of who revoked what needs keeping follows from the deployment's own
     * obligations, so nothing is discarded unless an operator says how long is long enough.
     *
     * @throws \Exception
     */
    public function testTheAuditTrailIsKeptIndefinitelyUnlessARetentionIsSet(): void
    {
        $this->assertNull($this->sut()->getVciStatusListAuditRetention());
    }


    /**
     * @throws \Exception
     */
    public function testReadsTheConfiguredAuditRetention(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
            'P1Y',
        ));

        $this->assertSame(1, $sut->getVciStatusListAuditRetention()?->y);
    }


    /**
     * A retention of no time would delete every row the moment it was written, which is a way of asking
     * for no trail at all rather than a retention policy. Leaving the option out is how that is said.
     *
     * @throws \Exception
     */
    public function testRejectsAnAuditRetentionOfNoTime(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
            'PT0S',
        ))->getVciStatusListAuditRetention();
    }


    /**
     * @throws \Exception
     */
    public function testRejectsAnAuditRetentionWhichIsNotADuration(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
            365,
        ))->getVciStatusListAuditRetention();
    }


    /**
     * @throws \Exception
     */
    public function testRejectsAnInvertedAuditRetentionGivenAsAnInterval(): void
    {
        $inverted = new DateInterval('P1Y');
        $inverted->invert = 1;

        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_STATUS_LIST_AUDIT_RETENTION,
            $inverted,
        ))->getVciStatusListAuditRetention();
    }


    /**
     * @throws \Exception
     */
    public function testVciCacheIsNotConfiguredByDefault(): void
    {
        $this->assertNull($this->sut()->getVciCacheAdapterClass());
        $this->assertSame([], $this->sut()->getVciCacheAdapterArguments());
    }


    /**
     * @throws \Exception
     */
    public function testCanGetVciCacheAdapterOptions(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_VCI_CACHE_ADAPTER => ArrayAdapter::class,
            ModuleConfig::OPTION_VCI_CACHE_ADAPTER_ARGUMENTS => ['openidVci'],
        ]));

        $this->assertSame(ArrayAdapter::class, $sut->getVciCacheAdapterClass());
        $this->assertSame(['openidVci'], $sut->getVciCacheAdapterArguments());
    }


    /**
     * @throws \Exception
     */
    public function testDidCacheMaxDurationDefaultsToSixHours(): void
    {
        $this->assertSame(6, $this->sut()->getVciDidCacheMaxDuration()->h);
    }


    /**
     * @throws \Exception
     */
    public function testCanGetDidCacheMaxDuration(): void
    {
        $this->assertSame(
            30,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_DID_CACHE_MAX_DURATION,
                'PT30M',
            ))->getVciDidCacheMaxDuration()->i,
        );
    }


    /**
     * @throws \Exception
     */
    public function testDidResolutionHasNoDestinationExemptionsByDefault(): void
    {
        $this->assertSame([], $this->sut()->getVciDidOutboundAllowedHosts());
        $this->assertSame([], $this->sut()->getVciDidOutboundAllowedCidrs());
    }


    /**
     * @throws \Exception
     */
    public function testCanGetDidDestinationExemptions(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_HOSTS => ['wallet.internal.example', 123],
            ModuleConfig::OPTION_VCI_DID_OUTBOUND_ALLOWED_CIDRS => ['10.1.2.3/32', null],
        ]));

        // Non-string entries are dropped rather than handed to the policy.
        $this->assertSame(['wallet.internal.example'], $sut->getVciDidOutboundAllowedHosts());
        $this->assertSame(['10.1.2.3/32'], $sut->getVciDidOutboundAllowedCidrs());
    }


    /**
     * The general outbound exemptions exist so this deployment can reach addresses it operates itself.
     * A DID names its own destination and is supplied by whoever is being authenticated, so inheriting
     * them here would let that party send this deployment to any of them.
     *
     * @throws \Exception
     */
    public function testDidResolutionDoesNotInheritTheGeneralOutboundExemptions(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS => ['rp.internal.example'],
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_CIDRS => ['10.0.0.0/8'],
        ]));

        $this->assertSame([], $sut->getVciDidOutboundAllowedHosts());
        $this->assertSame([], $sut->getVciDidOutboundAllowedCidrs());
    }


    /**
     * Stricter than the general outbound default, which is Preferred.
     *
     * @throws \Exception
     */
    public function testDidAddressPinningModeDefaultsToRequired(): void
    {
        $this->assertSame(
            AddressPinningModeEnum::Required,
            $this->sut()->getVciDidAddressPinningMode(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testCanGetDidAddressPinningModeFromEnumOrString(): void
    {
        $this->assertSame(
            AddressPinningModeEnum::Disabled,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
                AddressPinningModeEnum::Disabled,
            ))->getVciDidAddressPinningMode(),
        );

        $this->assertSame(
            AddressPinningModeEnum::Disabled,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
                AddressPinningModeEnum::Disabled->value,
            ))->getVciDidAddressPinningMode(),
        );
    }


    /**
     * Preferred proceeds unpinned wherever pinning turns out to be unavailable, which is the one thing
     * a fetch whose destination is chosen from outside must not do. Refused while the configuration is
     * read, so the admin screens report it rather than an issuance failing later.
     *
     * @throws \Exception
     */
    public function testRejectsPreferredDidAddressPinningMode(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
            AddressPinningModeEnum::Preferred,
        ))->getVciDidAddressPinningMode();
    }


    /**
     * @throws \Exception
     */
    public function testRejectsAnUnknownDidAddressPinningMode(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_DID_ADDRESS_PINNING_MODE,
            'whenever-convenient',
        ))->getVciDidAddressPinningMode();
    }


    /**
     * The default is what the module did before the option existed.
     *
     * @throws \Exception
     */
    public function testIssuerIdentifierModeDefaultsToDidJwk(): void
    {
        $sut = $this->sut();

        $this->assertSame(VciIssuerIdentifierModeEnum::DidJwk, $sut->getVciIssuerIdentifierMode());
        $this->assertNull($sut->getVciIssuerDidIdentifier());
        $this->assertSame(VciIssuerIdentifierModeEnum::DidJwk, $sut->getVciIssuerIdentifier()->getMode());
    }


    /**
     * @throws \Exception
     */
    public function testIssuerIdentifierModeAcceptsAnEnumCaseOrItsValue(): void
    {
        $this->assertSame(
            VciIssuerIdentifierModeEnum::Https,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
                VciIssuerIdentifierModeEnum::Https,
            ))->getVciIssuerIdentifierMode(),
        );

        $this->assertSame(
            VciIssuerIdentifierModeEnum::Https,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
                'https',
            ))->getVciIssuerIdentifierMode(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testRejectsAnUnknownIssuerIdentifierMode(): void
    {
        $this->expectException(ConfigurationError::class);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
            'did:sov',
        ))->getVciIssuerIdentifierMode();
    }


    /**
     * @throws \Exception
     */
    public function testResolvesTheConfiguredDidWebIdentifier(): void
    {
        $identifier = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidWeb,
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:example.org',
        ]))->getVciIssuerIdentifier();

        $this->assertTrue($identifier->isIssuingUnderDidWeb());
        $this->assertSame('did:web:example.org', $identifier->getDidWeb());
    }


    /**
     * The state the publish-after-mode-change rule rests on: the identifier is still configured, so
     * its document is still published, but nothing is issued under it any more.
     *
     * @throws \Exception
     */
    public function testKeepsADidWebIdentifierConfiguredUnderAnotherMode(): void
    {
        $identifier = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE => VciIssuerIdentifierModeEnum::DidJwk,
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER => 'did:web:example.org',
        ]))->getVciIssuerIdentifier();

        $this->assertFalse($identifier->isIssuingUnderDidWeb());
        $this->assertSame('did:web:example.org', $identifier->getDidWeb());
    }


    /**
     * @throws \Exception
     */
    public function testRejectsDidWebModeWithoutAnIdentifierToIssueUnder(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_ISSUER_IDENTIFIER_MODE,
            VciIssuerIdentifierModeEnum::DidWeb,
        ))->getVciIssuerIdentifier();
    }


    /**
     * Refused where it is configured rather than after credentials have been issued under it. These
     * are all syntactically DIDs; none of them is one this library could ever resolve.
     *
     * @throws \Exception
     */
    #[DataProvider('unresolvableDidWebIdentifierDataProvider')]
    public function testRejectsADidWebIdentifierWhichCouldNotBeResolved(string $identifier): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER,
            $identifier,
        ))->getVciIssuerDidIdentifier();
    }


    /**
     * @return array<string,array{string}>
     */
    public static function unresolvableDidWebIdentifierDataProvider(): array
    {
        return [
            'single label host' => ['did:web:localhost'],
            'IPv4 literal' => ['did:web:127.0.0.1'],
            'percent encoded segment' => ['did:web:example.org:%2Fetc'],
            'another method' => ['did:key:z6Mk'],
            'not a DID at all' => ['https://example.org'],
            'carries a fragment' => ['did:web:example.org#0'],
        ];
    }


    /**
     * An option left as an empty string is the same as not setting it, since a deployment which
     * cleared the value meant to stop publishing rather than to publish under nothing.
     *
     * @throws \Exception
     */
    public function testTreatsABlankDidWebIdentifierAsNoneAtAll(): void
    {
        $this->assertNull(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_VCI_ISSUER_DID_IDENTIFIER, '  '))
                ->getVciIssuerDidIdentifier(),
        );
    }
}
