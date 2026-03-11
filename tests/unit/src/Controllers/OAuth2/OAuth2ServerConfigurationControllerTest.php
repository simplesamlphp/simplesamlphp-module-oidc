<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\OAuth2;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\OAuth2\OAuth2ServerConfigurationController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\OpMetadataService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\OAuth2\OAuth2ServerConfigurationController
 */
class OAuth2ServerConfigurationControllerTest extends TestCase
{
    final public const OIDC_OP_METADATA = [
        'issuer' => 'http://localhost',
        'authorization_endpoint' => 'http://localhost/authorization',
        'token_endpoint' => 'http://localhost/token',
    ];

    protected MockObject $opMetadataServiceMock;
    protected MockObject $routesMock;
    protected MockObject $moduleConfigMock;

    protected function setUp(): void
    {
        $this->opMetadataServiceMock = $this->createMock(OpMetadataService::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->opMetadataServiceMock->method('getMetadata')->willReturn(self::OIDC_OP_METADATA);
    }

    protected function mock(
        ?OpMetadataService $opMetadataService = null,
        ?Routes $routes = null,
        ?ModuleConfig $moduleConfig = null,
    ): OAuth2ServerConfigurationController {
        return new OAuth2ServerConfigurationController(
            $opMetadataService ?? $this->opMetadataServiceMock,
            $routes ?? $this->routesMock,
            $moduleConfig ?? $this->moduleConfigMock,
        );
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            OAuth2ServerConfigurationController::class,
            $this->mock(),
        );
    }

    public function testItReturnsConfigurationWithoutIntrospectionIfApiDisabled(): void
    {
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(true);

        $jsonResponseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(self::OIDC_OP_METADATA)
            ->willReturn($jsonResponseMock);

        $this->assertSame($jsonResponseMock, $this->mock()->__invoke());
    }

    public function testItReturnsConfigurationWithoutIntrospectionIfIntrospectionDisabled(): void
    {
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(false);

        $jsonResponseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(self::OIDC_OP_METADATA)
            ->willReturn($jsonResponseMock);

        $this->assertSame($jsonResponseMock, $this->mock()->__invoke());
    }

    public function testItReturnsConfigurationWithIntrospectionEndpointEnabled(): void
    {
        $this->moduleConfigMock->method('getApiEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionEndpointEnabled')->willReturn(true);

        $signatureAlgorithmBagMock = $this->createMock(SignatureAlgorithmBag::class);
        $signatureAlgorithmBagMock->method('getAllNamesUnique')->willReturn(['RS256', 'ES256']);

        $supportedAlgorithmsMock = $this->createMock(SupportedAlgorithms::class);
        $supportedAlgorithmsMock->method('getSignatureAlgorithmBag')->willReturn($signatureAlgorithmBagMock);

        $this->moduleConfigMock->method('getSupportedAlgorithms')->willReturn($supportedAlgorithmsMock);

        $introspectionEndpoint = 'http://localhost/introspect';
        $this->routesMock->method('urlApiOAuth2TokenIntrospection')->willReturn($introspectionEndpoint);

        $expectedConfiguration = self::OIDC_OP_METADATA;
        $expectedConfiguration[ClaimsEnum::IntrospectionEndpoint->value] = $introspectionEndpoint;
        $expectedConfiguration[ClaimsEnum::IntrospectionEndpointAuthMethodsSupported->value] = [
            ClientAuthenticationMethodsEnum::ClientSecretBasic->value,
            ClientAuthenticationMethodsEnum::ClientSecretPost->value,
            ClientAuthenticationMethodsEnum::PrivateKeyJwt->value,
            AccessTokenTypesEnum::Bearer->value,
        ];
        $expectedConfiguration[ClaimsEnum::IntrospectionEndpointAuthSigningAlgValuesSupported->value] = [
            'RS256',
            'ES256',
        ];

        $jsonResponseMock = $this->createMock(JsonResponse::class);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($expectedConfiguration)
            ->willReturn($jsonResponseMock);

        $this->assertSame($jsonResponseMock, $this->mock()->__invoke());
    }
}
