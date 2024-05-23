<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use Lcobucci\JWT\Signer\Rsa;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use SimpleSAML\Module\oidc\ModuleConfig;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\OpMetadataService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\OpMetadataService
 */
class OpMetadataServiceTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    /**
     * @throws Exception
     */
    public function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->moduleConfigMock->expects($this->once())->method('getOpenIDScopes')
            ->willReturn(['openid' => 'openid']);
        $this->moduleConfigMock->expects($this->once())->method('getIssuer')
            ->willReturn('http://localhost');
        $this->moduleConfigMock->method('getModuleUrl')
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
        $this->moduleConfigMock->method('getAcrValuesSupported')->willReturn(['1']);

        $signer = $this->createMock(Rsa::class);
        $signer->method('algorithmId')->willReturn('RS256');
        $this->moduleConfigMock->method('getProtocolSigner')->willReturn($signer);
    }

    /**
     * @throws \Exception
     */
    protected function prepareMockedInstance(): OpMetadataService
    {
        return new OpMetadataService($this->moduleConfigMock);
    }

    /**
     * @throws \Exception
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpMetadataService::class,
            $this->prepareMockedInstance()
        );
    }

    /**
     * @throws \Exception
     */
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
