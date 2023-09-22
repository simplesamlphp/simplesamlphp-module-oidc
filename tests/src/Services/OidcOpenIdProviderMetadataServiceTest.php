<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService
 */
class OidcOpenIdProviderMetadataServiceTest extends TestCase
{
    protected \PHPUnit\Framework\MockObject\MockObject $configurationServiceMock;

    public function setUp(): void
    {
        $this->configurationServiceMock = $this->createMock(\SimpleSAML\Module\oidc\ConfigurationService::class);

        $this->configurationServiceMock->expects($this->once())->method('getOpenIDScopes')
            ->willReturn(['openid' => 'openid']);
        $this->configurationServiceMock->expects($this->once())->method('getSimpleSAMLSelfURLHost')
            ->willReturn('http://localhost');
        $this->configurationServiceMock->method('getOpenIdConnectModuleURL')
            ->willReturnCallback(function ($path) {
                $paths = [
                    'authorize.php' => 'http://localhost/authorize.php',
                    'token.php' => 'http://localhost/token.php',
                    'userinfo.php' => 'http://localhost/userinfo.php',
                    'jwks.php' => 'http://localhost/jwks.php',
                    'logout.php' => 'http://localhost/logout.php',
                ];

                return $paths[$path] ?? null;
            });
        $this->configurationServiceMock->method('getAcrValuesSupported')->willReturn(['1']);
    }

    protected function prepareMockedInstance(): OidcOpenIdProviderMetadataService
    {
        return new OidcOpenIdProviderMetadataService($this->configurationServiceMock);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OidcOpenIdProviderMetadataService::class,
            $this->prepareMockedInstance()
        );
    }

    public function testItReturnsExpectedMetadata(): void
    {
        $this->assertSame(
            [
                'issuer' => 'http://localhost',
                'authorization_endpoint' => 'http://localhost/authorize.php',
                'token_endpoint' => 'http://localhost/token.php',
                'userinfo_endpoint' => 'http://localhost/userinfo.php',
                'end_session_endpoint' => 'http://localhost/logout.php',
                'jwks_uri' => 'http://localhost/jwks.php',
                'scopes_supported' => ['openid'],
                'response_types_supported' => ['code', 'token', 'id_token', 'id_token token'],
                'subject_types_supported' => ['public'],
                'id_token_signing_alg_values_supported' => ['RS256'],
                'code_challenge_methods_supported' => ['plain', 'S256'],
                'token_endpoint_auth_methods_supported' => ['client_secret_post', 'client_secret_basic'],
                'request_parameter_supported' => false,
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'claims_parameter_supported' => true,
                'acr_values_supported' => ['1'],
                'backchannel_logout_supported' => true,
                'backchannel_logout_session_supported' => true,
            ],
            $this->prepareMockedInstance()->getMetadata()
        );
    }
}
