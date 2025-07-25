<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit;

use DateInterval;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;
use stdClass;

#[CoversClass(ModuleConfig::class)]
class ModuleConfigTest extends TestCase
{
    protected string $fileName;
    protected array $overrides;
    protected MockObject $sspConfigMock;

    protected array $moduleConfig = [
        ModuleConfig::OPTION_ISSUER => 'http://test.issuer',

        ModuleConfig::OPTION_TOKEN_AUTHORIZATION_CODE_TTL => 'PT10M',
        ModuleConfig::OPTION_TOKEN_REFRESH_TOKEN_TTL => 'P1M',
        ModuleConfig::OPTION_TOKEN_ACCESS_TOKEN_TTL => 'PT1H',

        ModuleConfig::OPTION_CRON_TAG => 'hourly',

        ModuleConfig::OPTION_TOKEN_SIGNER => Sha256::class,

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

        ModuleConfig::OPTION_FEDERATION_TOKEN_SIGNER => Sha256::class,
        ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_FILENAME =>
            ModuleConfig::DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME,
        ModuleConfig::OPTION_PKI_FEDERATION_PRIVATE_KEY_PASSPHRASE => 'abc123',
        ModuleConfig::OPTION_PKI_FEDERATION_CERTIFICATE_FILENAME =>
            ModuleConfig::DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME,
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
    private MockObject $sspBridgeModuleMock;
    private MockObject $sspBridgeUtilsConfigMock;

    protected function setUp(): void
    {
        $this->fileName = ModuleConfig::DEFAULT_FILE_NAME;
        $this->sspConfigMock = $this->createMock(Configuration::class);
        $this->overrides = [];

        $this->sspBridgeMock = $this->createMock(SspBridge::class);

        $this->sspBridgeUtilsMock = $this->createMock(SspBridge\Utils::class);

        $this->sspBridgeUtilsConfigMock = $this->createMock(Config::class);
        $this->sspBridgeUtilsConfigMock->method('getCertPath')
            ->willReturnCallback(fn(string $filename): string => '/path/to/cert' . $filename);
        $this->sspBridgeUtilsHttpMock = $this->createMock(HTTP::class);

        $this->sspBridgeModuleMock = $this->createMock(SspBridge\Module::class);
        $this->sspBridgeModuleMock->method('getModuleUrl')
            ->willReturn('http://sample.test/' . ModuleConfig::MODULE_NAME);

        $this->sspBridgeMock->method('utils')->willReturn($this->sspBridgeUtilsMock);
        $this->sspBridgeMock->method('module')->willReturn($this->sspBridgeModuleMock);

        $this->sspBridgeUtilsMock->method('http')->willReturn($this->sspBridgeUtilsHttpMock);
        $this->sspBridgeUtilsMock->method('config')->willReturn($this->sspBridgeUtilsConfigMock);
    }

    protected function sut(
        ?string $fileName = null,
        ?array $overrides = null,
        ?Configuration $sspConfig = null,
        ?SspBridge $sspBridge = null,
    ): ModuleConfig {
        $fileName ??= $this->fileName;
        $overrides ??= $this->overrides;
        $sspConfig ??= $this->sspConfigMock;
        $sspBridge ??= $this->sspBridgeMock;

        return new ModuleConfig(
            $fileName,
            $overrides,
            $sspConfig,
            $sspBridge,
        );
    }

    public function testCanGetCommonOptions(): void
    {
        $this->assertSame(ModuleConfig::MODULE_NAME, $this->sut()->moduleName());

        $this->assertInstanceOf(DateInterval::class, $this->sut()->getAuthCodeDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getAccessTokenDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getRefreshTokenDuration());

        $this->assertSame(
            $this->moduleConfig[ModuleConfig::OPTION_AUTH_SOURCE],
            $this->sut()->getDefaultAuthSourceId(),
        );
    }

    /**
     * @throws \Exception
     */
    public function testSigningKeyNameCanBeCustomized(): void
    {
        // Test default cert and pem
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME,
            $this->sut()->getProtocolCertPath(),
        );
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            $this->sut()->getProtocolPrivateKeyPath(),
        );

        // Set customized
        $this->overrides[ModuleConfig::OPTION_PKI_PRIVATE_KEY_FILENAME] = 'myPrivateKey.key';
        $this->overrides[ModuleConfig::OPTION_PKI_CERTIFICATE_FILENAME] = 'myCertificate.crt';
        $this->assertStringContainsString('myCertificate.crt', $this->sut()->getProtocolCertPath());
        $this->assertStringContainsString('myPrivateKey.key', $this->sut()->getProtocolPrivateKeyPath());
    }

    public function testCanGetSspConfig(): void
    {
        $this->assertInstanceOf(Configuration::class, $this->sut()->sspConfig());
    }

    public function testCanGetModuleUrl(): void
    {
        $this->assertStringContainsString(ModuleConfig::MODULE_NAME, $this->sut()->getModuleUrl('test'));
    }

    public function testCanGetOpenIdScopes(): void
    {
        $this->assertNotEmpty($this->sut()->getScopes());
    }

    public function testCanGetProtocolSigner(): void
    {
        $this->assertInstanceOf(Signer::class, $this->sut()->getProtocolSigner());
    }

    public function testCanGetProtocolPrivateKeyPassphrase(): void
    {
        $this->overrides[ModuleConfig::OPTION_PKI_PRIVATE_KEY_PASSPHRASE] = 'test';
        $this->assertNotEmpty($this->sut()->getProtocolPrivateKeyPassPhrase());
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

    public function testCanGetCommonFederationOptions(): void
    {
        $this->assertFalse($this->sut()->getFederationEnabled());
        $this->assertInstanceOf(Signer::class, $this->sut()->getFederationSigner());
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME,
            $this->sut()->getFederationPrivateKeyPath(),
        );
        $this->assertNotEmpty($this->sut()->getFederationPrivateKeyPassPhrase());
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME,
            $this->sut()->getFederationCertPath(),
        );
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
        $this->assertNotEmpty($this->sut()->getHomepageUri());
        $this->assertNotEmpty($this->sut()->getOrganizationUri());
        $this->assertNotEmpty($this->sut()->getFederationCacheAdapterClass());
        $this->assertIsArray($this->sut()->getFederationCacheAdapterArguments());
        $this->assertNotEmpty($this->sut()->getFederationCacheMaxDurationForFetched());
        $this->assertNotEmpty($this->sut()->getFederationTrustAnchors());
        $this->assertNotEmpty($this->sut()->getFederationTrustAnchorIds());
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

    public function testThrowsIfInvalidSignerProvided(): void
    {
        $this->overrides[ModuleConfig::OPTION_TOKEN_SIGNER] = stdClass::class;
        $this->expectException(ConfigurationError::class);
        $this->sut()->getProtocolSigner();
    }

    public function testCanGetEncryptionKey(): void
    {
        $this->sspBridgeUtilsConfigMock->expects($this->once())->method('getSecretSalt')
        ->willReturn('secretSalt');

        $this->assertSame('secretSalt', $this->sut()->getEncryptionKey());
    }

    public function testCanGetProtocolCacheConfiguration(): void
    {
        $this->assertNotEmpty($this->sut()->getProtocolCacheAdapterClass());
        $this->assertIsArray($this->sut()->getProtocolCacheAdapterArguments());

        $this->assertInstanceOf(DateInterval::class, $this->sut()->getProtocolUserEntityCacheDuration());
        $this->assertInstanceOf(DateInterval::class, $this->sut()->getProtocolClientEntityCacheDuration());
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

    public function testCanGetProtocolNewCertPath(): void
    {
        $this->assertNull($this->sut()->getProtocolNewCertPath());

        $sut = $this->sut(
            overrides: [ModuleConfig::OPTION_PKI_NEW_CERTIFICATE_FILENAME => 'new-cert'],
        );

        $this->assertStringContainsString('new-cert', $sut->getProtocolNewCertPath());
    }

    public function testCanGetFederationNewCertPath(): void
    {
        $this->assertNull($this->sut()->getFederationNewCertPath());

        $sut = $this->sut(
            overrides: [ModuleConfig::OPTION_PKI_FEDERATION_NEW_CERTIFICATE_FILENAME => 'new-cert'],
        );

        $this->assertStringContainsString('new-cert', $sut->getFederationNewCertPath());
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
}
