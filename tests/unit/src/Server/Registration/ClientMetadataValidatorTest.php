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
        $this->moduleConfigMock->method('getDcrImpersonationProtectionEnabled')->willReturn(true);
        // Default: the OP advertises a single supported ACR.
        $this->moduleConfigMock->method('getAcrValuesSupported')->willReturn(['urn:mace:incommon:iap:silver']);
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

    public function testValidRequestUrisPass(): void
    {
        // https URIs, including one with a fragment (OIDC Core allows a content-hash fragment on request_uri).
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'request_uris' => [
                'https://client.example.org/request-object',
                'https://client.example.org/request-object#sha256hash',
            ],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testRequestUrisMustBeArray(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'request_uris' => 'https://client.example.org/ro'],
            'invalid_client_metadata',
            'request_uris must be an array',
        );
    }

    public function testNonHttpsRequestUriIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'request_uris' => ['http://client.example.org/ro']],
            'invalid_client_metadata',
            'request_uris',
        );
    }

    public function testSubjectTypePublicIsAccepted(): void
    {
        $metadata = ['redirect_uris' => ['https://client.example.org/cb'], 'subject_type' => 'public'];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testPairwiseSubjectTypeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'subject_type' => 'pairwise'],
            'invalid_client_metadata',
            'subject_type',
        );
    }

    /**
     * @dataProvider unsupportedFeatureMetadataProvider
     */
    public function testUnsupportedFeatureMetadataIsRejected(string $field, mixed $value): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], $field => $value],
            'invalid_client_metadata',
            'Unsupported metadata',
        );
    }

    public static function unsupportedFeatureMetadataProvider(): array
    {
        return [
            'sector_identifier_uri' => ['sector_identifier_uri', 'https://client.example.org/sector'],
            'userinfo_signed_response_alg' => ['userinfo_signed_response_alg', 'RS256'],
            'userinfo_encrypted_response_alg' => ['userinfo_encrypted_response_alg', 'RSA-OAEP'],
            'id_token_encrypted_response_alg' => ['id_token_encrypted_response_alg', 'RSA-OAEP'],
            'request_object_encryption_alg' => ['request_object_encryption_alg', 'RSA-OAEP'],
            'frontchannel_logout_uri' => ['frontchannel_logout_uri', 'https://client.example.org/fclo'],
            'frontchannel_logout_session_required' => ['frontchannel_logout_session_required', true],
        ];
    }

    public function testValidAdditionalMetadataPasses(): void
    {
        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'default_max_age' => 600,
            'require_auth_time' => true,
            'default_acr_values' => ['urn:mace:incommon:iap:silver'],
            'initiate_login_uri' => 'https://client.example.org/initiate',
            'software_id' => 'example-suite',
            'software_version' => '1.2.3',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNegativeDefaultMaxAgeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'default_max_age' => -5],
            'invalid_client_metadata',
            'default_max_age',
        );
    }

    public function testNonBooleanRequireAuthTimeIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'require_auth_time' => 'yes'],
            'invalid_client_metadata',
            'require_auth_time',
        );
    }

    public function testNonArrayDefaultAcrValuesIsRejected(): void
    {
        $this->assertRejected(
            ['redirect_uris' => ['https://client.example.org/cb'], 'default_acr_values' => 'silver'],
            'invalid_client_metadata',
            'default_acr_values',
        );
    }

    public function testUnsupportedDefaultAcrValueIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'default_acr_values' => ['urn:mace:incommon:iap:silver', 'urn:not:supported'],
            ],
            'invalid_client_metadata',
            'default_acr_values',
        );
    }

    public function testNativeClientRejectsRemoteHttpRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'application_type' => 'native',
            ],
            'invalid_redirect_uri',
            'native client',
        );
    }

    public function testNativeClientAllowsCustomSchemeAndLoopbackRedirectUris(): void
    {
        $metadata = [
            'redirect_uris' => [
                'com.example.app:/oauth2redirect',
                'http://localhost:1234/cb',
                'http://127.0.0.1/cb',
                'http://[::1]/cb',
            ],
            'application_type' => 'native',
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testWebImplicitClientRejectsNonHttpsRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['http://client.example.org/cb'],
                'response_types' => ['id_token'],
            ],
            'invalid_redirect_uri',
            'web client using the implicit grant',
        );
    }

    public function testWebImplicitClientRejectsLocalhostRedirectUri(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://localhost/cb'],
                'response_types' => ['id_token'],
            ],
            'invalid_redirect_uri',
            'web client using the implicit grant',
        );
    }

    public function testWebCodeClientIsNotConstrainedByImplicitRule(): void
    {
        // Default (web) client not using implicit: an http://localhost redirect stays allowed.
        $metadata = [
            'redirect_uris' => ['http://localhost/cb'],
            'response_types' => ['code'],
        ];

        $this->assertSame($metadata, $this->sut()->validate($metadata));
    }

    public function testNonHttpsInitiateLoginUriIsRejected(): void
    {
        $this->assertRejected(
            [
                'redirect_uris' => ['https://client.example.org/cb'],
                'initiate_login_uri' => 'http://client.example.org/x',
            ],
            'invalid_client_metadata',
            'initiate_login_uri',
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
        $moduleConfigMock->method('getDcrImpersonationProtectionEnabled')->willReturn(false);

        $metadata = [
            'redirect_uris' => ['https://client.example.org/cb'],
            'logo_uri' => 'https://evil.example.com/logo.png',
        ];

        $this->assertSame($metadata, (new ClientMetadataValidator($moduleConfigMock))->validate($metadata));
    }
}
