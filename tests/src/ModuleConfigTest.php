<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc;

use Exception;
use Lcobucci\JWT\Signer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

#[CoversClass(ModuleConfig::class)]
class ModuleConfigTest extends TestCase
{
    protected string $fileName;
    protected array $overrides;
    protected MockObject $sspConfigMock;
    protected function setUp(): void
    {
        $this->fileName = ModuleConfig::DEFAULT_FILE_NAME;
        $this->sspConfigMock = $this->createMock(Configuration::class);
        $this->overrides = [];
    }

    protected function mock(): ModuleConfig
    {
        return new ModuleConfig($this->fileName, $this->overrides, $this->sspConfigMock);
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
}
