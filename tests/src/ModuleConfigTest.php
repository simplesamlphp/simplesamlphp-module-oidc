<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc;

use Exception;
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

    protected function mock(): ModuleConfig
    {
        return new ModuleConfig($this->fileName, $this->overrides, $this->sspConfigMock, $this->sspBridgeMock);
    }

    /**
     * @throws Exception
     */
    public function testSigningKeyNameCanBeCustomized(): void
    {
        // Test default cert and pem
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME,
            $this->mock()->getProtocolCertPath()
        );
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME,
            $this->mock()->getProtocolPrivateKeyPath()
        );

        // Set customized
        $this->overrides[ModuleConfig::OPTION_PKI_PRIVATE_KEY_FILENAME] = 'myPrivateKey.key';
        $this->overrides[ModuleConfig::OPTION_PKI_CERTIFICATE_FILENAME] = 'myCertificate.crt';
        $this->assertStringContainsString('myCertificate.crt', $this->mock()->getProtocolCertPath());
        $this->assertStringContainsString('myPrivateKey.key', $this->mock()->getProtocolPrivateKeyPath());
    }

    public function testCanGetSspConfig(): void
    {
        $this->assertInstanceOf(Configuration::class, $this->mock()->sspConfig());
    }

    public function testCanGetModuleUrl(): void
    {
        $this->assertStringContainsString(ModuleConfig::MODULE_NAME, $this->mock()->getModuleUrl('test'));
    }

    public function testCanGetOpenIdScopes(): void
    {
        $this->assertNotEmpty($this->mock()->getOpenIDScopes());
    }

    public function testCanGetProtocolSigner(): void
    {
        $this->assertInstanceOf(Signer::class, $this->mock()->getProtocolSigner());
    }

    public function testCanGetProtocolPrivateKeyPassphrase(): void
    {
        $this->overrides[ModuleConfig::OPTION_PKI_PRIVATE_KEY_PASSPHRASE] = 'test';
        $this->assertNotEmpty($this->mock()->getProtocolPrivateKeyPassPhrase());
    }

    public function testCanGetAuthProcFilters(): void
    {
        $this->assertIsArray($this->mock()->getAuthProcFilters());
    }

    public function testCanGetIssuer(): void
    {
        $this->assertNotEmpty($this->mock()->getIssuer());
    }

    public function testGetsCurrentHostIfIssuerNotSetInConfig(): void
    {
        $this->sspBridgeUtilsHttpMock->expects($this->once())->method('getSelfURLHost')
            ->willReturn('sample');
        $this->overrides[ModuleConfig::OPTION_ISSUER] = null;
        $this->mock()->getIssuer();
    }

    public function testThrowsOnEmptyIssuer(): void
    {
        $this->overrides[ModuleConfig::OPTION_ISSUER] = '';
        $this->expectException(OidcServerException::class);

        $this->mock()->getIssuer();
    }

    public function testCanGetForcedAcrValueForCookieAuthentication(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION] = '1a';
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = ['1a'];
        $this->assertEquals('1a', $this->mock()->getForcedAcrValueForCookieAuthentication());
    }

    public function testCanGetUserIdentifierAttribute(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_USER_IDENTIFIER_ATTRIBUTE] = 'sample';
        $this->assertEquals('sample', $this->mock()->getUserIdentifierAttribute());
    }

    public function testCanGetCommonFederationOptions(): void
    {
        $this->assertInstanceOf(Signer::class, $this->mock()->getFederationSigner());
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_FEDERATION_PRIVATE_KEY_FILENAME,
            $this->mock()->getFederationPrivateKeyPath()
        );
        $this->assertNotEmpty($this->mock()->getFederationPrivateKeyPassPhrase());
        $this->assertStringContainsString(
            ModuleConfig::DEFAULT_PKI_FEDERATION_CERTIFICATE_FILENAME,
            $this->mock()->getFederationCertPath()
        );
        $this->assertNotEmpty($this->mock()->getFederationEntityStatementDuration());
        $this->assertNotEmpty($this->mock()->getFederationAuthorityHints());
    }

    public function testThrowsIfTryingToOverrideProtectedScopes(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES] = [
            'openid' => [
                'description' => 'openid',
            ]
        ];

        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfCustomScopeDoesNotHaveDescription(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_CUSTOM_SCOPES] = [
            'custom' => [],
        ];

        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfAcrIsNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = [123];

        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfAuthSourceNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = [123 => []];
        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfAuthSourceToAcrMapAcrNotArray(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => 123];
        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfAuthSourceToAcrMapAcrNotString(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => [123]];
        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfAuthSourceToAcrMapAcrNotAllowed(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_SOURCES_TO_ACR_VALUES_MAP] = ['abc' => ['acr']];
        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIForcedAcrValueForCookieAuthenticationNotAllowed(): void
    {
        $this->overrides[ModuleConfig::OPTION_AUTH_ACR_VALUES_SUPPORTED] = ['abc'];
        $this->overrides[ModuleConfig::OPTION_AUTH_FORCED_ACR_VALUE_FOR_COOKIE_AUTHENTICATION] = 'cba';
        $this->expectException(ConfigurationError::class);
        $this->mock();
    }

    public function testThrowsIfInvalidSignerProvided(): void
    {
        $this->overrides[ModuleConfig::OPTION_TOKEN_SIGNER] = \stdClass::class;
        $this->expectException(ConfigurationError::class);
        $this->mock()->getProtocolSigner();
    }
}
