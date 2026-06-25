<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Registration;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Registration\ClientMetadataValidator;

#[CoversClass(ClientMetadataValidator::class)]
class ClientMetadataValidatorTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        // Default: impersonation protection on.
        $this->moduleConfigMock->method('getOidcDcrImpersonationProtectionEnabled')->willReturn(true);
    }

    protected function sut(): ClientMetadataValidator
    {
        return new ClientMetadataValidator($this->moduleConfigMock);
    }

    /**
     * Assert that validating the given metadata is rejected with the expected OAuth error code and a hint
     * containing the given substring.
     */
    protected function assertRejected(array $metadata, string $expectedErrorType, string $expectedHintSubstring): void
    {
        try {
            $this->sut()->validate($metadata);
            $this->fail('Expected OidcServerException was not thrown.');
        } catch (OidcServerException $exception) {
            $this->assertSame($expectedErrorType, $exception->getErrorType());
            $this->assertStringContainsString($expectedHintSubstring, (string)$exception->getHint());
        }
    }

    public function testValidMetadataPasses(): void
    {
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_name' => 'Example',
            'logo_uri' => 'https://client.example.org/logo.png',
            'policy_uri' => 'https://client.example.org/policy',
            'tos_uri' => 'https://client.example.org/tos',
            'client_uri' => 'https://marketing.example.net/',
            'contacts' => ['admin@example.org'],
            'application_type' => 'web',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNativeRedirectUriIsAllowed(): void
    {
        $metadata = ['redirect_uris' => ['com.example.app:/callback']];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testMissingRedirectUrisIsRejected(): void
    {
        $this->assertRejected(['client_name' => 'Example'], 'invalid_redirect_uri', 'redirect_uris is required');
    }

    public function testEmptyRedirectUrisIsRejected(): void
    {
        $this->assertRejected(['redirect_uris' => []], 'invalid_redirect_uri', 'redirect_uris is required');
    }

    public function testRedirectUriWithoutSchemeIsRejected(): void
    {
        $this->assertRejected(['redirect_uris' => ['not-a-uri']], 'invalid_redirect_uri', 'invalid');
    }

    public function testInvalidLogoUriIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'logo_uri' => 'not a url'],
            'invalid_client_metadata',
            'logo_uri',
        );
    }

    public function testContactsMustBeArray(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'contacts' => 'admin@example.org'],
            'invalid_client_metadata',
            'contacts',
        );
    }

    public function testInvalidApplicationTypeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'application_type' => 'desktop'],
            'invalid_client_metadata',
            'application_type',
        );
    }

    public function testImpersonationProtectionRejectsMismatchedHost(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'logo_uri' => 'https://evil.example.com/logo.png'],
            'invalid_client_metadata',
            'impersonation protection',
        );
    }

    public function testImpersonationProtectionAllowsClientUriOnDifferentHost(): void
    {
        // client_uri is intentionally excluded from the host check.
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_uri' => 'https://marketing.example.net/',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testImpersonationProtectionCanBeDisabled(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getOidcDcrImpersonationProtectionEnabled')->willReturn(false);

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'logo_uri' => 'https://evil.example.com/logo.png',
        ];

        $this->assertSame($metadata, (new ClientMetadataValidator($moduleConfigMock))->validate($metadata));
    }
}
