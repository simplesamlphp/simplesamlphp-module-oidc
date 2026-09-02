<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\JwtVcIssuerConfigurationController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\JsonResponse;

#[CoversClass(JwtVcIssuerConfigurationController::class)]
#[AllowMockObjectsWithoutExpectations]
class JwtVcIssuerConfigurationControllerTest extends TestCase
{
    protected const string ISSUER = 'https://issuer.example.org';

    protected const string JWKS_URI = 'https://issuer.example.org/simplesaml/module.php/oidc/jwks';


    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('getModuleUrl')->willReturn(self::JWKS_URI);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            static fn(?array $data, int $status = 200, array $headers = []): JsonResponse =>
                new JsonResponse($data, $status, $headers),
        );

        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): JwtVcIssuerConfigurationController
    {
        return new JwtVcIssuerConfigurationController(
            $this->moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
        );
    }


    public function testPublishesTheIssuerAndItsKeySet(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);

        $configuration = json_decode((string)$this->sut()->configuration()->getContent(), true);

        $this->assertSame(self::ISSUER, $configuration[ClaimsEnum::Issuer->value] ?? null);
        $this->assertSame(self::JWKS_URI, $configuration[ClaimsEnum::JwksUri->value] ?? null);
    }


    public function testRefusesWhileIssuanceIsDisabled(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::DidJwk);

        $this->expectException(OidcServerException::class);

        $this->sut();
    }


    /**
     * Under the `https` issuer identity this document is how an SD-JWT VC verifier finds the key set
     * to check an already issued credential against, so switching issuance off must not withdraw it.
     */
    public function testKeepsServingWhileCredentialsAreVerifiedThroughIt(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willReturn(VciIssuerIdentifierModeEnum::Https);

        $configuration = json_decode((string)$this->sut()->configuration()->getContent(), true);

        $this->assertSame(self::ISSUER, $configuration[ClaimsEnum::Issuer->value] ?? null);
    }


    /**
     * A malformed identity mode is reported on the configuration screen which owns it, and must not
     * decide this endpoint one way or the other by throwing out of the constructor.
     */
    public function testAMalformedIssuerIdentityModeLeavesTheEndpointAsItWas(): void
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciIssuerIdentifierMode')
            ->willThrowException(new ConfigurationError('nope'));

        $this->expectException(OidcServerException::class);

        $this->sut();
    }
}
