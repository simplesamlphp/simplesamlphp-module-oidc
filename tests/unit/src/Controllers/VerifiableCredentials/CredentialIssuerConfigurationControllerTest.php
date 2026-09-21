<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerConfigurationController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\CredentialIssuerMetadataService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * What the document contains is CredentialIssuerMetadataServiceTest's subject. This endpoint publishes
 * that document, and refuses to when there is none to publish.
 */
#[CoversClass(CredentialIssuerConfigurationController::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialIssuerConfigurationControllerTest extends TestCase
{
    protected const array METADATA = [
        ClaimsEnum::CredentialIssuer->value => 'https://issuer.com',
        ClaimsEnum::CredentialEndpoint->value => 'https://issuer.com/credential',
    ];


    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $credentialIssuerMetadataServiceMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->credentialIssuerMetadataServiceMock = $this->createMock(CredentialIssuerMetadataService::class);

        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->credentialIssuerMetadataServiceMock->method('getMetadata')->willReturn(self::METADATA);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            /**
             * @param ?array<array-key,mixed> $data
             */
            static fn(?array $data = null): JsonResponse => new JsonResponse($data),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function sut(): CredentialIssuerConfigurationController
    {
        return new CredentialIssuerConfigurationController(
            $this->moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
            $this->credentialIssuerMetadataServiceMock,
        );
    }


    /**
     * Published as the service built it, with nothing added or taken away here, since the Entity
     * Configuration publishes the same document and the two must not differ.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testPublishesTheDocumentTheServiceBuilds(): void
    {
        $content = $this->sut()->configuration()->getContent();

        $this->assertIsString($content);
        $this->assertSame(self::METADATA, json_decode($content, true, 512, JSON_THROW_ON_ERROR));
    }


    /**
     * The constructor is the gate: with Verifiable Credentials switched off there is no metadata to
     * publish, and nothing further in this controller should be reachable.
     */
    public function testRefusesToPublishAnythingWhenCredentialsAreDisabled(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);

        $this->credentialIssuerMetadataServiceMock->expects($this->never())->method('getMetadata');
        $this->loggerServiceMock->expects($this->once())->method('warning');

        $this->expectException(OidcServerException::class);

        $this->sut();
    }
}
