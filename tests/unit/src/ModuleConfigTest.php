<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use DateInterval;
use Defuse\Crypto\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\StatusListKeyProfileEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListPool;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\TrustMarkStatusEndpointUsagePolicyEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\SupportedSerializers;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairConfigBag;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

#[CoversClass(ModuleConfig::class)]
class ModuleConfigTest extends TestCase
{
    protected string $fileName;
    protected array $overrides;
    protected MockObject $sspConfigMock;

    protected array $moduleConfig = [
        ModuleConfig::OPTION_ISSUER => 'http://test.issuer',

        ModuleConfig::OPTION_PROTOCOL_SIGNATURE_KEY_PAIRS => [
            [
                ModuleConfig::KEY_ALGORITHM => \SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum::RS256,
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

        ModuleConfig::OPTION_PROTOCOL_CACHE_ADAPTER => \Symfony\Component\Cache\Adapter\ArrayAdapter::class,
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

        $this->sspBridgeUtilsMock = $this->createMock(SspBridge\Utils::class);

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
            method_exists(\SimpleSAML\Database::class, ModuleConfig::SSP_PRIMARY_READ_METHOD),
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
}
