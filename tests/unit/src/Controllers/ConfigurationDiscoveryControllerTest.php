<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\ConfigurationDiscoveryController;
use SimpleSAML\Module\oidc\Services\OpMetadataService;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\ConfigurationDiscoveryController
 */
class ConfigurationDiscoveryControllerTest extends TestCase
{
    final public const OIDC_OP_METADATA = [
        'issuer' => 'http://localhost',
        'authorization_endpoint' => 'http://localhost/authorization',
        'token_endpoint' => 'http://localhost/token',
        'userinfo_endpoint' => 'http://localhost/userinfo',
        'jwks_uri' => 'http://localhost/jwks',
        'signed_jwks_uri' => 'http://localhost/signed-jwks',
        'scopes_supported' => ['openid'],
        'response_types_supported' => ['code', 'token', 'id_token', 'id_token token'],
        'subject_types_supported' => ['public'],
        'id_token_signing_alg_values_supported' => ['RS256'],
        'code_challenge_methods_supported' => ['plain', 'S256'],
        'end_session_endpoint' => 'http://localhost/end-session',
    ];

    protected MockObject $oidcOpenIdProviderMetadataServiceMock;
    protected MockObject $serverRequestMock;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->oidcOpenIdProviderMetadataServiceMock  = $this->createMock(OpMetadataService::class);
        $this->oidcOpenIdProviderMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);

        $this->serverRequestMock = $this->createMock(ServerRequest::class);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            ConfigurationDiscoveryController::class,
            new ConfigurationDiscoveryController($this->oidcOpenIdProviderMetadataServiceMock),
        );
    }

    protected function getStubbedInstance(): ConfigurationDiscoveryController
    {
        return new ConfigurationDiscoveryController($this->oidcOpenIdProviderMetadataServiceMock);
    }

    public function testItReturnsOpenIdConnectConfiguration(): void
    {
        $this->assertSame(
            json_decode($this->getStubbedInstance()->__invoke()->getContent(), true),
            self::OIDC_OP_METADATA,
        );
    }
}
