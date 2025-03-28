<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services;

use Lcobucci\JWT\Signer\Rsa;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Services\OpMetadataService
 */
class OpMetadataServiceTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $claimTranslatorExtractorMock;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->moduleConfigMock->expects($this->once())->method('getScopes')
            ->willReturn(['openid' => 'openid']);
        $this->moduleConfigMock->expects($this->once())->method('getIssuer')
            ->willReturn('http://localhost');
        $this->moduleConfigMock->method('getModuleUrl')
            ->willReturnCallback(function ($path) {
                $paths = [
                    RoutesEnum::Authorization->value => 'http://localhost/authorization',
                    RoutesEnum::Token->value => 'http://localhost/token',
                    RoutesEnum::UserInfo->value => 'http://localhost/userinfo',
                    RoutesEnum::Jwks->value => 'http://localhost/jwks',
                    RoutesEnum::EndSession->value => 'http://localhost/end-session',
                ];

                return $paths[$path] ?? null;
            });
        $this->moduleConfigMock->method('getAcrValuesSupported')->willReturn(['1']);

        $signer = $this->createMock(Rsa::class);
        $signer->method('algorithmId')->willReturn('RS256');
        $this->moduleConfigMock->method('getProtocolSigner')->willReturn($signer);

        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
    }

    /**
     * @throws \Exception
     */
    protected function sut(
        ?ModuleConfig $moduleConfig = null,
        ?ClaimTranslatorExtractor $claimTranslatorExtractor = null,
    ): OpMetadataService {
        $moduleConfig = $moduleConfig ?? $this->moduleConfigMock;
        $claimTranslatorExtractor = $claimTranslatorExtractor ?? $this->claimTranslatorExtractorMock;

        return new OpMetadataService(
            $moduleConfig,
            $claimTranslatorExtractor,
        );
    }

    /**
     * @throws \Exception
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OpMetadataService::class,
            $this->sut(),
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
                'authorization_endpoint' => 'http://localhost/authorization',
                'token_endpoint' => 'http://localhost/token',
                'userinfo_endpoint' => 'http://localhost/userinfo',
                'end_session_endpoint' => 'http://localhost/end-session',
                'jwks_uri' => 'http://localhost/jwks',
                'scopes_supported' => ['openid'],
                'response_types_supported' => ['code', 'token', 'id_token', 'id_token token'],
                'subject_types_supported' => ['public'],
                'id_token_signing_alg_values_supported' => ['RS256'],
                'code_challenge_methods_supported' => ['plain', 'S256'],
                'token_endpoint_auth_methods_supported' => [
                    'client_secret_post',
                    'client_secret_basic',
                    'private_key_jwt',
                ],
                'token_endpoint_auth_signing_alg_values_supported' => [
                    'RS256',
                ],
                'request_parameter_supported' => true,
                'request_object_signing_alg_values_supported' => ['none', 'RS256'],
                'request_uri_parameter_supported' => false,
                'grant_types_supported' => ['authorization_code', 'refresh_token'],
                'claims_parameter_supported' => true,
                'acr_values_supported' => ['1'],
                'backchannel_logout_supported' => true,
                'backchannel_logout_session_supported' => true,
            ],
            $this->sut()->getMetadata(),
        );
    }

    public function testCanShowClaimsSupportedClaim(): void
    {
        $this->moduleConfigMock->method('getProtocolDiscoveryShowClaimsSupported')->willReturn(true);
        $this->claimTranslatorExtractorMock->method('getSupportedClaims')->willReturn(['sample']);

        $sut = $this->sut();
        $this->assertArrayHasKey(
            ClaimsEnum::ClaimsSupported->value,
            $sut->getMetadata(),
        );

        $this->assertTrue(
            in_array('sample', $sut->getMetadata()[ClaimsEnum::ClaimsSupported->value], true),
        );
    }
}
