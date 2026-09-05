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
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListExpiryLaneEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\Module\oidc\Utils\ResponseTypeGrantTypeCorrespondence;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;
use SimpleSAML\OpenID\Codebooks\ResponseTypesEnum;
use SimpleSAML\OpenID\Codebooks\ScopesEnum;
use SimpleSAML\OpenID\Codebooks\TokenEndpointAuthMethodsEnum;
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
use ValueError;

/**
 * Two branches are deliberately left uncovered here, both defensive depth rather than reachable
 * behaviour. `getVciStatusListEnabled()` refuses to enable Status Lists on a SimpleSAMLphp which cannot
 * read past its secondaries, and it asks that of the class through `method_exists()`, which a unit test
 * cannot influence; version 7 requires a SimpleSAMLphp which has the method, so the guard is always
 * satisfied. `getVciIssuerIdentifier()` catches a `VciIssuerIdentifier` which could not be built, but
 * the only pairing that constructor rejects is the one the check immediately above it has already
 * refused, with the option names in hand.
 */
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


    /*****************************************************************************************************************
     * Issuer, Pushed Authorization Requests and Request Objects.
     ****************************************************************************************************************/

    /**
     * Whether the issuer was stated matters on its own: an unstated one is derived from the host the
     * request arrived on, so it can differ between requests to the same deployment.
     *
     * @throws \Exception
     */
    public function testIssuerIsReportedAsConfiguredWhenItIsSet(): void
    {
        $this->assertTrue($this->sut()->isIssuerConfigured());
    }


    /**
     * A cleared issuer is not a stated one. Reporting it as configured would have the administration
     * interface claim the OP issues under the empty string.
     *
     * @throws \Exception
     */
    #[DataProvider('unstatedIssuerDataProvider')]
    public function testIssuerIsNotReportedAsConfiguredWhenItIsNotStated(?string $issuer): void
    {
        $this->assertFalse(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_ISSUER, $issuer))->isIssuerConfigured(),
        );
    }


    /**
     * @return array<string,array{?string}>
     */
    public static function unstatedIssuerDataProvider(): array
    {
        return [
            'never set' => [null],
            'cleared' => [''],
        ];
    }


    /**
     * @throws \Exception
     */
    public function testPushedAuthorizationRequestUrisLastTenMinutesUnlessConfiguredOtherwise(): void
    {
        $this->assertSame(10, $this->sut()->getParRequestUriTtl()->i);

        $this->assertSame(
            30,
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_PAR_REQUEST_URI_TTL, 'PT30S'))
                ->getParRequestUriTtl()->s,
        );
    }


    /**
     * Opt-in, both of them: a deployment which has not said otherwise accepts an ordinary authorization
     * request, and turning either on refuses requests which worked the request before.
     *
     * @throws \Exception
     */
    public function testPushedAuthorizationRequestsAreOptionalUntilAnOperatorRequiresThem(): void
    {
        $this->assertFalse($this->sut()->getRequirePushedAuthorizationRequests());

        $this->assertTrue(
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_REQUIRE_PUSHED_AUTHORIZATION_REQUESTS,
                true,
            ))->getRequirePushedAuthorizationRequests(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testRequestObjectsMayBeUnsignedUntilAnOperatorRequiresSignatures(): void
    {
        $this->assertFalse($this->sut()->getRequireSignedRequestObject());

        $this->assertTrue(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_REQUIRE_SIGNED_REQUEST_OBJECT, true))
                ->getRequireSignedRequestObject(),
        );
    }


    /**
     * Fetching a Request Object named by `request_uri` is an outbound request this OP makes on a
     * stranger say-so, so both limits exist and both hold a value without being configured.
     *
     * @throws \Exception
     */
    public function testRequestUriFetchesAreBoundedWithoutBeingConfigured(): void
    {
        $sut = $this->sut();

        $this->assertSame(5, $sut->getRequestUriFetchTimeout());
        $this->assertSame(102400, $sut->getRequestUriMaxSizeBytes());
    }


    /**
     * @throws \Exception
     */
    public function testReadsTheConfiguredRequestUriFetchLimits(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_REQUEST_URI_FETCH_TIMEOUT => 2,
            ModuleConfig::OPTION_REQUEST_URI_MAX_SIZE_BYTES => 4096,
        ]));

        $this->assertSame(2, $sut->getRequestUriFetchTimeout());
        $this->assertSame(4096, $sut->getRequestUriMaxSizeBytes());
    }


    /**
     * The option distinguishes an explicit null (allow any prefix) from an absent one (deny), which is
     * why it is read from the raw configuration array. A value which is neither says nothing about what
     * to allow, and this is the allowlist for a fetch driven by an unknown party, so it denies rather
     * than guesses.
     *
     * @throws \Exception
     */
    public function testFederationRequestUriPrefixesDenyEverythingWhenTheOptionIsNotAList(): void
    {
        $this->assertSame(
            [],
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES,
                'https://rp.example.org/',
            ))->getFederationRequestUriAllowedPrefixes(),
        );
    }


    /*****************************************************************************************************************
     * Outbound destination policy.
     ****************************************************************************************************************/

    /**
     * Asserted as the literal scheme rather than against the library constant, because the point of the
     * default is that this OP makes no plaintext request unless a deployment asks for one.
     *
     * @throws \Exception
     */
    public function testOutboundRequestsAreLimitedToHttpsUnlessConfiguredOtherwise(): void
    {
        $this->assertSame(['https'], $this->sut()->getOutboundAllowedSchemes());
    }


    /**
     * All three lists are filtered to strings and re-indexed, so a malformed entry can neither reach the
     * destination policy nor turn the list into a map.
     *
     * @throws \Exception
     */
    public function testOutboundListsKeepOnlyStringEntriesAndStayLists(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_SCHEMES => ['https', 42, 'http', ['nested']],
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_HOSTS => [null, 'rp.example.org', 7],
            ModuleConfig::OPTION_OUTBOUND_ALLOWED_CIDRS => ['10.0.0.0/8', false, '192.168.0.0/16'],
        ]));

        $this->assertSame(['https', 'http'], $sut->getOutboundAllowedSchemes());
        $this->assertSame(['rp.example.org'], $sut->getOutboundAllowedHosts());
        $this->assertSame(['10.0.0.0/8', '192.168.0.0/16'], $sut->getOutboundAllowedCidrs());
    }


    /**
     * Nothing is exempt from the address checks until a deployment names it.
     *
     * @throws \Exception
     */
    public function testNoHostOrAddressRangeIsExemptedByDefault(): void
    {
        $sut = $this->sut();

        $this->assertSame([], $sut->getOutboundAllowedHosts());
        $this->assertSame([], $sut->getOutboundAllowedCidrs());
    }


    /**
     * Unlike did:web resolution, which insists on pinning, the general outbound policy prefers it:
     * pinning is not available on every platform, and refusing every outbound request there would
     * disable federation rather than harden it.
     *
     * @throws \Exception
     */
    public function testOutboundAddressPinningDefaultsToPreferred(): void
    {
        $this->assertSame(AddressPinningModeEnum::Preferred, $this->sut()->getOutboundAddressPinningMode());
    }


    /**
     * Read from an enum case or from the string behind it, since every neighbouring option in the
     * configuration file is a scalar and a deployment will reach for one here too.
     *
     * @throws \Exception
     */
    #[DataProvider('outboundAddressPinningModeDataProvider')]
    public function testOutboundAddressPinningIsReadFromAnEnumCaseOrItsValue(
        mixed $configured,
        AddressPinningModeEnum $expected,
    ): void {
        $this->assertSame(
            $expected,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
                $configured,
            ))->getOutboundAddressPinningMode(),
        );
    }


    /**
     * @return array<string,array{mixed,\SimpleSAML\OpenID\Codebooks\AddressPinningModeEnum}>
     */
    public static function outboundAddressPinningModeDataProvider(): array
    {
        return [
            'enum case' => [AddressPinningModeEnum::Required, AddressPinningModeEnum::Required],
            'backing value' => ['required', AddressPinningModeEnum::Required],
            'disabled as a string' => ['disabled', AddressPinningModeEnum::Disabled],
        ];
    }


    /**
     * Refused rather than quietly treated as the default, since the two directions this could be
     * guessed in are check nothing and refuse everything.
     *
     * @throws \Exception
     */
    #[DataProvider('invalidOutboundAddressPinningModeDataProvider')]
    public function testRejectsAnUnknownOutboundAddressPinningMode(mixed $configured): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE);

        $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_OUTBOUND_ADDRESS_PINNING_MODE,
            $configured,
        ))->getOutboundAddressPinningMode();
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function invalidOutboundAddressPinningModeDataProvider(): array
    {
        return [
            'unknown string' => ['sometimes'],
            'not a string' => [true],
            'an array' => [['required']],
        ];
    }


    /*****************************************************************************************************************
     * The sets this OP advertises, accepts on registration, and offers in the administration interface.
     ****************************************************************************************************************/

    /**
     * These four sets are hardcoded so that what is advertised in discovery metadata, what the
     * registration validator accepts, and what the client form offers cannot drift apart. Restating the
     * literals here would assert nothing, so what is checked is that each value is a real member of its
     * codebook and that no value is listed twice.
     *
     * @throws \Exception
     */
    public function testAdvertisedResponseModesAreDistinctAndKnown(): void
    {
        $responseModes = $this->sut()->getSupportedResponseModes();

        $this->assertNotEmpty($responseModes);
        $this->assertSame(array_values(array_unique($responseModes)), $responseModes);

        foreach ($responseModes as $responseMode) {
            $this->assertInstanceOf(
                ResponseModesEnum::class,
                ResponseModesEnum::tryFrom($responseMode),
                sprintf('Advertised response mode "%s" is not a known one.', $responseMode),
            );
        }
    }


    /**
     * @throws \Exception
     */
    public function testAdvertisedResponseTypesAreDistinctAndKnown(): void
    {
        $responseTypes = $this->sut()->getSupportedResponseTypes();

        $this->assertNotEmpty($responseTypes);
        $this->assertSame(array_values(array_unique($responseTypes)), $responseTypes);

        foreach ($responseTypes as $responseType) {
            $this->assertInstanceOf(
                ResponseTypesEnum::class,
                ResponseTypesEnum::tryFrom($responseType),
                sprintf('Advertised response type "%s" is not a known one.', $responseType),
            );
        }
    }


    /**
     * @throws \Exception
     */
    public function testRegistrableGrantTypesAreDistinctAndKnown(): void
    {
        $grantTypes = $this->sut()->getSupportedGrantTypes();

        $this->assertNotEmpty($grantTypes);
        $this->assertSame(array_values(array_unique($grantTypes)), $grantTypes);

        foreach ($grantTypes as $grantType) {
            $this->assertInstanceOf(
                GrantTypesEnum::class,
                GrantTypesEnum::tryFrom($grantType),
                sprintf('Registrable grant type "%s" is not a known one.', $grantType),
            );
        }
    }


    /**
     * @throws \Exception
     */
    public function testRegistrableTokenEndpointAuthMethodsAreDistinctAndKnown(): void
    {
        $authMethods = $this->sut()->getSupportedTokenEndpointAuthMethods();

        $this->assertNotEmpty($authMethods);
        $this->assertSame(array_values(array_unique($authMethods)), $authMethods);

        foreach ($authMethods as $authMethod) {
            $this->assertInstanceOf(
                TokenEndpointAuthMethodsEnum::class,
                TokenEndpointAuthMethodsEnum::tryFrom($authMethod),
                sprintf('Registrable token endpoint auth method "%s" is not a known one.', $authMethod),
            );
        }
    }


    /**
     * The two sets are not independent. OpenID Connect Dynamic Client Registration requires a client
     * registering a response type to also register the grant type that goes with it, and this module
     * states that correspondence in one place. So every advertised response type must appear there, and
     * the grant types it demands must be ones a client may actually register: were `id_token` advertised
     * while `implicit` was not registrable, a client following the specification would be rejected for
     * doing exactly what it was told to do.
     *
     * @throws \Exception
     */
    public function testEveryAdvertisedResponseTypeCanBeRegisteredWithTheGrantTypesItRequires(): void
    {
        $sut = $this->sut();
        $responseTypes = $sut->getSupportedResponseTypes();
        $grantTypes = $sut->getSupportedGrantTypes();
        $correspondence = ResponseTypeGrantTypeCorrespondence::map();

        foreach ($responseTypes as $responseType) {
            $this->assertArrayHasKey(
                $responseType,
                $correspondence,
                sprintf('Response type "%s" is advertised but names no required grant types.', $responseType),
            );
        }

        foreach (ResponseTypeGrantTypeCorrespondence::requiredGrantTypes($responseTypes) as $requiredGrantType) {
            $this->assertContains(
                $requiredGrantType,
                $grantTypes,
                sprintf(
                    'Grant type "%s" is required by an advertised response type but is not registrable.',
                    $requiredGrantType,
                ),
            );
        }
    }


    /**
     * The sets are checked for shape above, which does not say a capability was not dropped from one of
     * them: the drift test only walks what is advertised, so removing `code` outright would go unnoticed.
     * These are the flows this module actually implements -- `AuthCodeGrant`, `RefreshTokenGrant`, and
     * public clients which authenticate with no secret at all -- so an OP which stops offering them is
     * advertising less than it can do, and every client following that metadata loses the flow.
     *
     * @throws \Exception
     */
    public function testTheFlowsThisOpImplementsAreAlwaysOffered(): void
    {
        $sut = $this->sut();

        $this->assertContains(ResponseTypesEnum::Code->value, $sut->getSupportedResponseTypes());
        $this->assertContains(GrantTypesEnum::AuthorizationCode->value, $sut->getSupportedGrantTypes());
        $this->assertContains(GrantTypesEnum::RefreshToken->value, $sut->getSupportedGrantTypes());
        $this->assertContains(
            TokenEndpointAuthMethodsEnum::ClientSecretBasic->value,
            $sut->getSupportedTokenEndpointAuthMethods(),
        );
        $this->assertContains(
            TokenEndpointAuthMethodsEnum::None->value,
            $sut->getSupportedTokenEndpointAuthMethods(),
        );
    }


    /*****************************************************************************************************************
     * Encryption key, claim translation and back-channel logout.
     ****************************************************************************************************************/

    /**
     * Only whether a dedicated key is configured is reported, never the key itself: without one the
     * module falls back to the SimpleSAMLphp secret salt, and an administrator has no other way to see
     * which of the two is in use.
     *
     * @throws \Exception
     */
    public function testEncryptionKeyIsReportedAsConfiguredOnlyWhenOneIsSet(): void
    {
        $this->assertFalse($this->sut()->isEncryptionKeyConfigured());

        $this->assertTrue(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_ENCRYPTION_KEY, 'def0000...'))
                ->isEncryptionKeyConfigured(),
        );

        $this->assertFalse(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_ENCRYPTION_KEY, ''))
                ->isEncryptionKeyConfigured(),
        );
    }


    /**
     * Only the configured part of the table. The defaults, the user identifier attributes and the
     * per-scope prefixes are merged over it at runtime, so this getter answering with more than what
     * was configured would make the administration interface show a table nobody wrote.
     *
     * @throws \Exception
     */
    public function testReadsOnlyTheConfiguredPartOfTheClaimTranslationTable(): void
    {
        $this->assertSame([], $this->sut()->getSamlToOidcTranslateTable());

        $this->assertSame(
            ['name' => ['displayName']],
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_AUTH_SAML_TO_OIDC_TRANSLATE_TABLE,
                ['name' => ['displayName']],
            ))->getSamlToOidcTranslateTable(),
        );
    }


    /**
     * Read independently of the protocol and federation options, so that a deployment which relaxes TLS
     * verification to reach a Relying Party with a self-signed certificate does not relax it for
     * everything else this OP connects to.
     *
     * @throws \Exception
     */
    public function testBackChannelLogoutHttpClientOptionsAreSeparateFromTheOtherOnes(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_BACKCHANNEL_LOGOUT_HTTP_CLIENT_OPTIONS,
            ['verify' => false, 'timeout' => 3],
        ));

        $this->assertSame(['verify' => false, 'timeout' => 3], $sut->getBackChannelLogoutHttpClientOptions());
        $this->assertSame([], $sut->getProtocolHttpClientOptions());
        $this->assertSame([], $sut->getFederationHttpClientOptions());
        $this->assertSame([], $this->sut()->getBackChannelLogoutHttpClientOptions());
    }


    /*****************************************************************************************************************
     * Verifiable Credential Issuance signing keys.
     ****************************************************************************************************************/

    /**
     * An empty list is refused rather than carried until something tries to sign with it, which would
     * fail while issuing a credential rather than while reading the configuration.
     *
     * @throws \Exception
     */
    public function testRejectsAnEmptyVciSignatureKeyPairList(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('At least one');

        $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS, []))
            ->getVciSignatureKeyPairs();
    }


    /**
     * Both bags are built once and kept. Rebuilding the key pair bag per call would re-read the key
     * material from disk on every credential, nonce and Status List Token this OP signs.
     *
     * @throws \Exception
     */
    public function testTheVciSignatureKeyPairConfigBagIsBuiltOnceAndReused(): void
    {
        $sut = $this->sut(overrides: $this->withVciSignatureKeyPair());

        $configBag = $sut->getVciSignatureKeyPairConfigBag();

        $this->assertInstanceOf(SignatureKeyPairConfigBag::class, $configBag);
        $this->assertSame($configBag, $sut->getVciSignatureKeyPairConfigBag());
    }


    /**
     * The factory is expected exactly once, which is what says the answer was kept rather than rebuilt:
     * a mock handing back one shared bag would satisfy an identity assertion either way.
     *
     * @throws \Exception
     */
    public function testTheVciSignatureKeyPairBagIsBuiltOnceAndReused(): void
    {
        $signatureKeyPairBagFactoryMock = $this->createMock(SignatureKeyPairBagFactory::class);
        $signatureKeyPairBagFactoryMock->expects($this->once())
            ->method('fromConfig')
            ->willReturn(new SignatureKeyPairBag());

        $valueAbstractsMock = $this->createMock(ValueAbstracts::class);
        $valueAbstractsMock->method('signatureKeyPairBagFactory')->willReturn($signatureKeyPairBagFactoryMock);

        $sut = $this->sut(overrides: $this->withVciSignatureKeyPair(), valueAbstracts: $valueAbstractsMock);

        $keyPairBag = $sut->getVciSignatureKeyPairBag();

        $this->assertInstanceOf(SignatureKeyPairBag::class, $keyPairBag);
        $this->assertSame($keyPairBag, $sut->getVciSignatureKeyPairBag());
    }


    /**
     * The VCI key pair configuration this module ships as a working example, so that a test only has to
     * say which option it is exercising.
     *
     * @return array<string,mixed>
     */
    protected function withVciSignatureKeyPair(): array
    {
        return $this->withOption(
            ModuleConfig::OPTION_VCI_SIGNATURE_KEY_PAIRS,
            [
                [
                    ModuleConfig::KEY_ALGORITHM => SignatureAlgorithmEnum::RS256,
                    ModuleConfig::KEY_PRIVATE_KEY_FILENAME => 'oidc_module.key',
                    ModuleConfig::KEY_PUBLIC_KEY_FILENAME => 'oidc_module.crt',
                ],
            ],
        );
    }


    /*****************************************************************************************************************
     * Verifiable Credential Issuance credential configurations.
     ****************************************************************************************************************/

    /**
     * @throws \Exception
     */
    public function testReadsNoCredentialConfigurationForAnIdWhichIsNotDeclared(): void
    {
        $this->assertNull($this->sut()->getVciCredentialConfiguration('TestCredential'));
    }


    /**
     * @throws \Exception
     */
    public function testReadsADeclaredCredentialConfiguration(): void
    {
        $this->assertSame(
            ['format' => 'dc+sd-jwt'],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => ['format' => 'dc+sd-jwt'],
            ]))->getVciCredentialConfiguration('TestCredential'),
        );
    }


    /**
     * A credential configuration which is not a map of metadata is refused rather than returned for a
     * caller to trip over, since everything downstream reads it by key.
     *
     * @throws \Exception
     */
    public function testRejectsACredentialConfigurationWhichIsNotAMap(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('TestCredential');

        $this->sut(overrides: $this->withCredentialConfigurations(['TestCredential' => 'dc+sd-jwt']))
            ->getVciCredentialConfiguration('TestCredential');
    }


    /**
     * Every declared credential configuration is also a scope, since that is how a wallet asks for one.
     * With the capability off there are none, whatever is declared: offering the scopes of a capability
     * which is not being served would have the OP advertise credentials it will not issue.
     *
     * @throws \Exception
     */
    public function testCredentialConfigurationsBecomeScopesOnlyWhileIssuanceIsEnabled(): void
    {
        $configurations = $this->withCredentialConfigurations([
            'TestCredential' => [],
            'OtherCredential' => [],
        ]);

        $this->assertSame([], $this->sut(overrides: $configurations)->getVciScopes());

        $this->assertSame(
            [
                'TestCredential' => ['description' => 'TestCredential'],
                'OtherCredential' => ['description' => 'OtherCredential'],
            ],
            $this->sut(overrides: array_merge($configurations, [ModuleConfig::OPTION_VCI_ENABLED => true]))
                ->getVciScopes(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDeclaredCredentialConfigurationIdsAreListedAsStrings(): void
    {
        $this->assertSame(
            ['TestCredential', '7'],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => [],
                7 => [],
            ]))->getVciCredentialConfigurationIdsSupported(),
        );
    }


    /**
     * A credential request names the credential by its definition type rather than by the id this OP
     * files it under, so the two have to be matched up.
     *
     * @throws \Exception
     */
    public function testResolvesTheCredentialConfigurationIdForADeclaredCredentialDefinitionType(): void
    {
        $sut = $this->sut(overrides: $this->withCredentialConfigurations([
            'TestCredential' => [
                ClaimsEnum::CredentialDefinition->value => [
                    ClaimsEnum::Type->value => ['VerifiableCredential', 'TestCredential'],
                ],
            ],
        ]));

        $this->assertSame(
            'TestCredential',
            $sut->getVciCredentialConfigurationIdForCredentialDefinitionType(
                ['VerifiableCredential', 'TestCredential'],
            ),
        );
        $this->assertNull(
            $sut->getVciCredentialConfigurationIdForCredentialDefinitionType(['VerifiableCredential']),
        );
    }


    /**
     * Malformed entries are stepped over rather than matched against, so one broken configuration does
     * not stop the credential a wallet asked for from being found.
     *
     * @throws \Exception
     */
    public function testStepsOverMalformedConfigurationsWhileResolvingACredentialDefinitionType(): void
    {
        $sut = $this->sut(overrides: $this->withCredentialConfigurations([
            'NotAMap' => 'dc+sd-jwt',
            'NoDefinition' => ['format' => 'dc+sd-jwt'],
            'DefinitionIsNotAMap' => [ClaimsEnum::CredentialDefinition->value => 'VerifiableCredential'],
            'TestCredential' => [
                ClaimsEnum::CredentialDefinition->value => [
                    ClaimsEnum::Type->value => ['VerifiableCredential', 'TestCredential'],
                ],
            ],
        ]));

        $this->assertSame(
            'TestCredential',
            $sut->getVciCredentialConfigurationIdForCredentialDefinitionType(
                ['VerifiableCredential', 'TestCredential'],
            ),
        );
    }


    /**
     * The claim paths are what a credential is allowed to carry, so they are read from the credential
     * metadata, or from the older top-level `claims` key for a configuration written before the
     * metadata one existed.
     *
     * @throws \Exception
     */
    #[DataProvider('credentialClaimsLocationDataProvider')]
    public function testReadsTheValidClaimPathsWhereverTheClaimsAreDeclared(array $credentialConfiguration): void
    {
        $this->assertSame(
            [['given_name'], ['address', 'locality']],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => $credentialConfiguration,
            ]))->getVciValidCredentialClaimPathsFor('TestCredential'),
        );
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function credentialClaimsLocationDataProvider(): array
    {
        $claims = [
            [ClaimsEnum::Path->value => ['given_name']],
            [ClaimsEnum::Path->value => ['address', 'locality']],
        ];

        return [
            'under credential metadata' => [[ClaimsEnum::CredentialMetadata->value => [
                ClaimsEnum::Claims->value => $claims,
            ]]],
            'directly under claims' => [[ClaimsEnum::Claims->value => $claims]],
        ];
    }


    /**
     * A claim which names no path describes nothing this OP can fill in, and is dropped rather than
     * carried as a null path into whatever builds the credential.
     *
     * @throws \Exception
     */
    public function testDropsDeclaredClaimsWhichNameNoPath(): void
    {
        $this->assertSame(
            [['given_name']],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => [
                    ClaimsEnum::Claims->value => [
                        [ClaimsEnum::Path->value => ['given_name']],
                        ['mandatory' => true],
                        'not a claim at all',
                    ],
                ],
            ]))->getVciValidCredentialClaimPathsFor('TestCredential'),
        );
    }


    /**
     * Dropping a claim which names no path leaves the surviving entries under their original keys: the
     * getter filters without re-indexing. Both callers walk the result rather than index into it, so it
     * does not matter to them today -- but the shape is what it is, and one which reaches for position 0
     * or encodes the list as JSON would find a gap. Pinned so that adding `array_values()` is a decision
     * someone makes rather than one that happens quietly.
     *
     * @throws \Exception
     */
    public function testTheSurvivingClaimPathsKeepTheirOriginalKeys(): void
    {
        $this->assertSame(
            [1 => ['given_name']],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => [
                    ClaimsEnum::Claims->value => [
                        ['mandatory' => true],
                        [ClaimsEnum::Path->value => ['given_name']],
                    ],
                ],
            ]))->getVciValidCredentialClaimPathsFor('TestCredential'),
        );
    }


    /**
     * @throws \Exception
     */
    #[DataProvider('claimlessCredentialConfigurationDataProvider')]
    public function testReadsNoClaimPathsFromACredentialConfigurationWhichDeclaresNoUsableClaims(
        mixed $credentialConfiguration,
    ): void {
        $this->assertSame(
            [],
            $this->sut(overrides: $this->withCredentialConfigurations([
                'TestCredential' => $credentialConfiguration,
            ]))->getVciValidCredentialClaimPathsFor('TestCredential'),
        );
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function claimlessCredentialConfigurationDataProvider(): array
    {
        return [
            'configuration is not a map' => ['dc+sd-jwt'],
            'no claims declared' => [['format' => 'dc+sd-jwt']],
            'claims are not a list' => [[ClaimsEnum::Claims->value => 'given_name']],
        ];
    }


    /**
     * @throws \Exception
     */
    public function testReadsNoClaimPathsForACredentialConfigurationWhichIsNotDeclared(): void
    {
        $this->assertSame([], $this->sut()->getVciValidCredentialClaimPathsFor('TestCredential'));
    }


    /**
     * @throws \Exception
     */
    public function testReadsTheAttributeToClaimPathMapForACredentialConfiguration(): void
    {
        $map = ['givenName' => ['given_name']];

        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP,
            ['TestCredential' => $map],
        ));

        $this->assertSame(['TestCredential' => $map], $sut->getVciUserAttributeToCredentialClaimPathMap());
        $this->assertSame($map, $sut->getVciUserAttributeToCredentialClaimPathMapFor('TestCredential'));
    }


    /**
     * @throws \Exception
     */
    public function testReadsNoAttributeToClaimPathMapWhereThereIsNoUsableOne(): void
    {
        $this->assertSame([], $this->sut()->getVciUserAttributeToCredentialClaimPathMap());
        $this->assertSame([], $this->sut()->getVciUserAttributeToCredentialClaimPathMapFor('TestCredential'));

        $this->assertSame(
            [],
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_USER_ATTRIBUTE_TO_CREDENTIAL_CLAIM_PATH_MAP,
                ['TestCredential' => 'given_name'],
            ))->getVciUserAttributeToCredentialClaimPathMapFor('TestCredential'),
        );
    }


    /**
     * The credential configurations a test declares, which is what nearly every VCI getter reads from.
     *
     * @param array<array-key,mixed> $credentialConfigurations
     * @return array<string,mixed>
     */
    protected function withCredentialConfigurations(array $credentialConfigurations): array
    {
        return $this->withOption(
            ModuleConfig::OPTION_VCI_CREDENTIAL_CONFIGURATIONS_SUPPORTED,
            $credentialConfigurations,
        );
    }


    /*****************************************************************************************************************
     * Verifiable Credential Issuance durations, offers and contexts.
     ****************************************************************************************************************/

    /**
     * The issuer state is carried across the same authorization the authorization code is, so with
     * nothing configured it lasts exactly as long, rather than acquiring a default of its own which
     * could outlive the flow it belongs to.
     *
     * @throws \Exception
     */
    public function testIssuerStateLastsAsLongAsAnAuthorizationCodeUnlessConfiguredOtherwise(): void
    {
        // A distinctive authorization code lifetime, so that the issuer state following it is visible
        // rather than two defaults happening to agree.
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL,
            'PT13M',
        ));

        $this->assertSame(13, $sut->getVciIssuerStateDuration()->i);
        $this->assertSame(
            $sut->getAuthCodeDuration()->format('%y%m%d%h%i%s'),
            $sut->getVciIssuerStateDuration()->format('%y%m%d%h%i%s'),
        );

        $this->assertSame(
            7,
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_VCI_ISSUER_STATE_TTL, 'PT7M'))
                ->getVciIssuerStateDuration()->i,
        );
    }


    /**
     * @throws \Exception
     */
    public function testProofOfPossessionNoncesLastFiveMinutesUnlessConfiguredOtherwise(): void
    {
        $this->assertSame(5, $this->sut()->getVciNonceTtl()->i);

        $this->assertSame(
            30,
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_VCI_NONCE_TTL, 'PT30S'))
                ->getVciNonceTtl()->s,
        );
    }


    /**
     * Issuing to a client which was never registered is off until a deployment says otherwise, and when
     * it is on, the only redirect target accepted without registration is the credential offer scheme.
     *
     * @throws \Exception
     */
    public function testNonRegisteredClientsAreRefusedUntilAllowedAndAreThenBoundToTheOfferScheme(): void
    {
        $this->assertFalse($this->sut()->getVciAllowNonRegisteredClients());

        $this->assertSame(
            ['openid-credential-offer://'],
            $this->sut()->getVciAllowedRedirectUriPrefixesForNonRegisteredClients(),
        );

        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_VCI_ALLOW_NON_REGISTERED_CLIENTS => true,
            ModuleConfig::OPTION_VCI_ALLOWED_REDIRECT_URI_PREFIXES_FOR_NON_REGISTERED_CLIENTS =>
                ['haip://', 'openid-credential-offer://'],
        ]));

        $this->assertTrue($sut->getVciAllowNonRegisteredClients());
        $this->assertSame(
            ['haip://', 'openid-credential-offer://'],
            $sut->getVciAllowedRedirectUriPrefixesForNonRegisteredClients(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testReadsTheJsonLdContextDeclaredForACredentialConfiguration(): void
    {
        $context = ['@context' => ['https://www.w3.org/ns/credentials/v2']];

        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
            ['TestCredential' => $context],
        ));

        $this->assertSame(['TestCredential' => $context], $sut->getVciCredentialJsonLdContext());
        $this->assertSame($context, $sut->getVciCredentialJsonLdContextFor('TestCredential'));
    }


    /**
     * Answered as "none configured" rather than as an empty document, so that a caller can tell a
     * credential configuration which has no context from one whose context says nothing.
     *
     * @throws \Exception
     */
    public function testReadsNoJsonLdContextWhereThereIsNoDocument(): void
    {
        $this->assertSame([], $this->sut()->getVciCredentialJsonLdContext());
        $this->assertNull($this->sut()->getVciCredentialJsonLdContextFor('TestCredential'));

        $this->assertNull(
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_CREDENTIAL_JSON_LD_CONTEXT,
                ['TestCredential' => 'https://www.w3.org/ns/credentials/v2'],
            ))->getVciCredentialJsonLdContextFor('TestCredential'),
        );
    }


    /**
     * A lifetime is a duration string. Anything else is refused where it is written rather than at the
     * moment a credential is issued under it.
     *
     * @throws \Exception
     */
    public function testCredentialLifetimesRejectALifetimeWhichIsNotADurationString(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage('duration string');

        $this->sut(overrides: $this->withCredentialTtl(3600))->getVciCredentialTtls();
    }


    /**
     * The limit applies to whatever the request appears to come from, so it stays off until an operator
     * states that they know which address arrives at this OP.
     *
     * @throws \Exception
     */
    public function testStatusListRequestsAreUnlimitedUntilAnOperatorSaysOtherwise(): void
    {
        $this->assertSame(0, $this->sut()->getVciStatusListRequestsPerMinute());

        $this->assertSame(
            60,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE,
                60,
            ))->getVciStatusListRequestsPerMinute(),
        );
    }


    /**
     * A negative limit has no reading: it is neither a rate nor the absence of one, and taking it as
     * either would be a guess about a public endpoint wallets depend on.
     *
     * @throws \Exception
     */
    public function testRejectsANegativeStatusListRequestLimit(): void
    {
        $this->expectException(ConfigurationError::class);
        $this->expectExceptionMessage(ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE);

        $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_VCI_STATUS_LIST_REQUESTS_PER_MINUTE, -1))
            ->getVciStatusListRequestsPerMinute();
    }


    /*****************************************************************************************************************
     * API endpoints.
     ****************************************************************************************************************/

    /**
     * Every API capability is off until it is switched on, including the ones behind the master switch:
     * each is a separate decision to accept requests over the network.
     *
     * @throws \Exception
     */
    public function testEveryApiCapabilityIsOffUntilItIsSwitchedOn(): void
    {
        $sut = $this->sut();

        $this->assertFalse($sut->getApiEnabled());
        $this->assertFalse($sut->getApiVciCredentialOfferEndpointEnabled());
        $this->assertFalse($sut->getApiVciCredentialStatusEndpointEnabled());
        $this->assertFalse($sut->getApiOAuth2TokenIntrospectionEndpointEnabled());
    }


    /**
     * One option at a time, and the other three are asserted to stay off. Turning all four on together
     * would pass just as well if two of these getters read the same option as each other, which is the
     * mistake worth catching: each of them gates a different endpoint.
     *
     * @throws \Exception
     */
    #[DataProvider('apiCapabilityOptionDataProvider')]
    public function testEachApiCapabilityIsReadFromItsOwnOption(string $option): void
    {
        $capabilities = $this->apiCapabilities($this->sut(overrides: $this->withOption($option, true)));

        foreach ($capabilities as $capabilityOption => $isEnabled) {
            $this->assertSame(
                $capabilityOption === $option,
                $isEnabled,
                sprintf('Enabling "%s" decided the answer for "%s".', $option, $capabilityOption),
            );
        }
    }


    /**
     * @return array<string,array{string}>
     */
    public static function apiCapabilityOptionDataProvider(): array
    {
        return [
            'the API itself' => [ModuleConfig::OPTION_API_ENABLED],
            'credential offer endpoint' => [ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED],
            'credential status endpoint' => [ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED],
            'token introspection endpoint' =>
                [ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED],
        ];
    }


    /**
     * Each API capability keyed by the option which is meant to govern it.
     *
     * @return array<string,bool>
     */
    protected function apiCapabilities(ModuleConfig $sut): array
    {
        return [
            ModuleConfig::OPTION_API_ENABLED => $sut->getApiEnabled(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED =>
                $sut->getApiVciCredentialOfferEndpointEnabled(),
            ModuleConfig::OPTION_API_VCI_CREDENTIAL_STATUS_ENDPOINT_ENABLED =>
                $sut->getApiVciCredentialStatusEndpointEnabled(),
            ModuleConfig::OPTION_API_OAUTH2_TOKEN_INTROSPECTION_ENDPOINT_ENABLED =>
                $sut->getApiOAuth2TokenIntrospectionEndpointEnabled(),
        ];
    }


    /*****************************************************************************************************************
     * Dynamic Client Registration.
     ****************************************************************************************************************/

    /**
     * Off by default: with it on, this OP accepts client registrations from the network.
     *
     * @throws \Exception
     */
    public function testDynamicClientRegistrationIsDisabledUntilItIsEnabled(): void
    {
        $this->assertFalse($this->sut()->getDcrEnabled());

        $this->assertTrue(
            $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_DCR_ENABLED, true))->getDcrEnabled(),
        );
    }


    /**
     * @throws \Exception
     */
    public function testDynamicClientRegistrationIsOpenUnlessGatedByAnInitialAccessToken(): void
    {
        $this->assertSame(DcrRegistrationAuthEnum::Open, $this->sut()->getDcrRegistrationAuth());

        $this->assertSame(
            DcrRegistrationAuthEnum::InitialAccessToken,
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_DCR_REGISTRATION_AUTH,
                DcrRegistrationAuthEnum::InitialAccessToken->value,
            ))->getDcrRegistrationAuth(),
        );
    }


    /**
     * Note the failure mode: unlike the neighbouring enum-valued options, this one is read with
     * `from()`, so an unknown mode raises a `ValueError` rather than a `ConfigurationError` naming the
     * option. Pinned as it stands rather than changed here, since the two behave differently for an
     * administrator reading the resulting error.
     *
     * @throws \Exception
     */
    public function testRejectsAnUnknownDynamicClientRegistrationAuthMode(): void
    {
        $this->expectException(ValueError::class);

        $this->sut(overrides: $this->withOption(ModuleConfig::OPTION_DCR_REGISTRATION_AUTH, 'invitation'))
            ->getDcrRegistrationAuth();
    }


    /**
     * Initial Access Tokens are issued out of band, so the allowlist is empty until a deployment fills
     * it. Entries which could not be a bearer token are dropped rather than compared against, so that a
     * blank one cannot become a token which authorizes registration.
     *
     * @throws \Exception
     */
    public function testReadsOnlyUsableInitialAccessTokens(): void
    {
        $this->assertSame([], $this->sut()->getDcrInitialAccessTokens());

        $this->assertSame(
            ['first-token', 'second-token'],
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_DCR_INITIAL_ACCESS_TOKENS,
                ['first-token', '', null, 42, ['nested'], 'second-token'],
            ))->getDcrInitialAccessTokens(),
        );
    }


    /**
     * Impersonation protection is on unless a deployment turns it off, and dynamically registered
     * clients are usable immediately unless a deployment asks to review them first.
     *
     * @throws \Exception
     */
    public function testTheRegistrationDefaultsFavourTheSaferAndTheSimplerAnswer(): void
    {
        $sut = $this->sut();

        $this->assertTrue($sut->getDcrImpersonationProtectionEnabled());
        $this->assertTrue($sut->getDcrRegisteredClientsEnabled());
    }


    /**
     * Turned off one at a time, since both default to on: switching both together would pass even if
     * the two getters read the same option, and they mean different things -- one decides whether a
     * registration is refused, the other whether the client it created can be used yet.
     *
     * @throws \Exception
     */
    #[DataProvider('registrationSwitchOptionDataProvider')]
    public function testTheRegistrationSwitchesAreIndependentOfEachOther(string $option): void
    {
        $sut = $this->sut(overrides: $this->withOption($option, false));

        $switches = [
            ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED =>
                $sut->getDcrImpersonationProtectionEnabled(),
            ModuleConfig::OPTION_DCR_REGISTERED_CLIENTS_ENABLED => $sut->getDcrRegisteredClientsEnabled(),
        ];

        foreach ($switches as $switchOption => $isEnabled) {
            $this->assertSame(
                $switchOption !== $option,
                $isEnabled,
                sprintf('Turning off "%s" decided the answer for "%s".', $option, $switchOption),
            );
        }
    }


    /**
     * @return array<string,array{string}>
     */
    public static function registrationSwitchOptionDataProvider(): array
    {
        return [
            'impersonation protection' => [ModuleConfig::OPTION_DCR_IMPERSONATION_PROTECTION_ENABLED],
            'registered clients enabled' => [ModuleConfig::OPTION_DCR_REGISTERED_CLIENTS_ENABLED],
        ];
    }


    /**
     * A dynamic client which registers without naming a scope is assigned every scope this OP supports,
     * so the default set has to follow the supported ones rather than a list of its own. A scope this
     * deployment added is what shows that: it is in neither the standard set nor any list the getter
     * could be carrying.
     *
     * @throws \Exception
     */
    public function testClientsRegisteringWithoutAScopeGetEverySupportedScope(): void
    {
        $sut = $this->sut(overrides: $this->withOption(
            ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES,
            ['api' => ['description' => 'API access']],
        ));

        $defaultScopes = $sut->getDcrDefaultScopes();

        $this->assertContains('api', $defaultScopes);
        $this->assertContains(ScopesEnum::OpenId->value, $defaultScopes);
        $this->assertContains(ScopesEnum::OfflineAccess->value, $defaultScopes);
        $this->assertSame(array_keys($sut->getScopes()), $defaultScopes);
    }


    /**
     * @throws \Exception
     */
    public function testReadsOnlyUsableConfiguredDefaultScopes(): void
    {
        $this->assertSame(
            ['openid', 'profile'],
            $this->sut(overrides: $this->withOption(
                ModuleConfig::OPTION_DCR_DEFAULT_SCOPES,
                ['openid', '', null, 13, 'profile'],
            ))->getDcrDefaultScopes(),
        );
    }


    /*****************************************************************************************************************
     * The attribute a user is emailed at.
     ****************************************************************************************************************/

    /**
     * Per authentication source, since which attribute carries the address is a property of the source
     * rather than of this module, with a deployment-wide answer behind it.
     *
     * @throws \Exception
     */
    public function testTheEmailAttributeIsReadPerAuthenticationSourceWithADeploymentWideFallback(): void
    {
        $sut = $this->sut(overrides: array_merge($this->overrides, [
            ModuleConfig::OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME => 'emailAddress',
            ModuleConfig::OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP => [
                'default-sp' => 'eduPersonPrincipalName',
                'broken-sp' => ['mail'],
            ],
        ]));

        $this->assertSame(
            ['default-sp' => 'eduPersonPrincipalName', 'broken-sp' => ['mail']],
            $sut->getAuthSourcesToUsersEmailAttributeMap(),
        );
        $this->assertSame('eduPersonPrincipalName', $sut->getUsersEmailAttributeNameForAuthSourceId('default-sp'));
        $this->assertSame('emailAddress', $sut->getUsersEmailAttributeNameForAuthSourceId('other-sp'));
        $this->assertSame('emailAddress', $sut->getUsersEmailAttributeNameForAuthSourceId('broken-sp'));
        $this->assertSame('emailAddress', $sut->getDefaultUsersEmailAttributeName());
    }


    /**
     * @throws \Exception
     */
    public function testTheEmailAttributeIsMailUnlessConfiguredOtherwise(): void
    {
        $sut = $this->sut();

        $this->assertSame([], $sut->getAuthSourcesToUsersEmailAttributeMap());
        $this->assertSame('mail', $sut->getDefaultUsersEmailAttributeName());
        $this->assertSame('mail', $sut->getUsersEmailAttributeNameForAuthSourceId('default-sp'));
    }
}
