<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Laminas\Diactoros\ServerRequest;
use SimpleSAML\Module\oidc\Controller\OpenIdConnectDiscoverConfigurationController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\OidcOpenIdProviderMetadataService;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\OpenIdConnectDiscoverConfigurationController
 */
class OpenIdConnectDiscoverConfigurationControllerTest extends TestCase
{
    public const OIDC_OP_METADATA = [
        'issuer' => 'http://localhost',
        'authorization_endpoint' => 'http://localhost/authorize.php',
        'token_endpoint' => 'http://localhost/token.php',
        'userinfo_endpoint' => 'http://localhost/userinfo.php',
        'jwks_uri' => 'http://localhost/jwks.php',
        'scopes_supported' => ['openid'],
        'response_types_supported' => ['code', 'token', 'id_token', 'id_token token'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['plain', 'S256'],
        'end_session_endpoint' => 'http://localhost/logout.php',
    ];
    /**
     * \PHPUnit\Framework\MockObject\MockObject
     */
    protected $oidcOpenIdProviderMetadataServiceMock;
    /**
     * \PHPUnit\Framework\MockObject\MockObject
     */
    protected $serverRequestMock;

    protected function setUp(): void
    {
        $this->oidcOpenIdProviderMetadataServiceMock  = $this->createMock(OidcOpenIdProviderMetadataService::class);
        $this->oidcOpenIdProviderMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpenIdConnectDiscoverConfigurationController::class,
            new OpenIdConnectDiscoverConfigurationController($this->oidcOpenIdProviderMetadataServiceMock)
        );
    }

    protected function getStubbedInstance(): OpenIdConnectDiscoverConfigurationController
    {
        return new OpenIdConnectDiscoverConfigurationController($this->oidcOpenIdProviderMetadataServiceMock);
    }

    public function testItReturnsOpenIdConnectConfiguration(): void
    {
        $this->assertSame(
            $this->getStubbedInstance()->__invoke($this->serverRequestMock)->getPayload(),
            self::OIDC_OP_METADATA
        );
    }
}
