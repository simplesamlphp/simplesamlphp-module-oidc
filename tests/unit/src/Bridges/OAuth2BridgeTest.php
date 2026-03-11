<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Bridges;

use Defuse\Crypto\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\OAuth2Bridge;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\ModuleConfig;

#[CoversClass(OAuth2Bridge::class)]
#[UsesClass(OidcException::class)]
class OAuth2BridgeTest extends TestCase
{
    private ModuleConfig&MockObject $moduleConfig;
    private OAuth2Bridge $bridge;


    protected function setUp(): void
    {
        $this->moduleConfig = $this->createMock(ModuleConfig::class);
        $this->bridge = new OAuth2Bridge($this->moduleConfig);
    }


    public function testEncryptDecryptWithPasswordFromConfig(): void
    {
        $password = 'secret-password';
        $this->moduleConfig->method('getEncryptionKey')->willReturn($password);

        $unencrypted = 'secret-data-2';
        $encrypted = $this->bridge->encrypt($unencrypted);

        $this->assertNotEquals($unencrypted, $encrypted);

        $decrypted = $this->bridge->decrypt($encrypted);
        $this->assertEquals($unencrypted, $decrypted);
    }

    public function testEncryptDecryptWithExplicitKey(): void
    {
        $key = Key::createNewRandomKey();

        $unencrypted = 'secret-data-3';
        $encrypted = $this->bridge->encrypt($unencrypted, $key);

        $this->assertNotEquals($unencrypted, $encrypted);

        $decrypted = $this->bridge->decrypt($encrypted, $key);
        $this->assertEquals($unencrypted, $decrypted);
    }

    public function testEncryptDecryptWithExplicitPassword(): void
    {
        $password = 'secret-password-explicit';

        $unencrypted = 'secret-data-4';
        $encrypted = $this->bridge->encrypt($unencrypted, $password);

        $this->assertNotEquals($unencrypted, $encrypted);

        $decrypted = $this->bridge->decrypt($encrypted, $password);
        $this->assertEquals($unencrypted, $decrypted);
    }


    public function testDecryptThrowsOidcExceptionOnInvalidData(): void
    {
        $this->moduleConfig->method('getEncryptionKey')->willReturn('secret-password');

        $this->expectException(OidcException::class);
        $this->expectExceptionMessage('Error decrypting data:');

        $this->bridge->decrypt('invalid-encrypted-data');
    }
}
