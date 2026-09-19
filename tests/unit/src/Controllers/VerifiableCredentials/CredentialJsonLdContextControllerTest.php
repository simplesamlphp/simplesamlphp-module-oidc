<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialJsonLdContextController;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * The endpoint serving a credential configuration's JSON-LD context document, at the URL
 * `VciContextResolver` lists in a credential's `@context` when a document is configured.
 *
 * Like the credential, issuer configuration and nonce endpoints it refuses to be built at all while VCI
 * is off. Built, it answers the configured document as JSON-LD, and a 404 with no body for a
 * configuration ID which has none.
 */
#[CoversClass(CredentialJsonLdContextController::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialJsonLdContextControllerTest extends TestCase
{
    protected const string CREDENTIAL_CONFIGURATION_ID = 'EmployeeBadge';

    protected const array CONTEXT_DOCUMENT = [
        '@context' => [
            '@version' => 1.1,
            'EmployeeBadge' => 'https://example.org/vocab#EmployeeBadge',
        ],
    ];


    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;

    protected MockObject $loggerServiceMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);

        $this->routesMock = $this->createMock(Routes::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    protected function sut(): CredentialJsonLdContextController
    {
        return new CredentialJsonLdContextController(
            $this->moduleConfigMock,
            $this->routesMock,
            $this->loggerServiceMock,
        );
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(CredentialJsonLdContextController::class, $this->sut());
    }


    public function testRefusesToBeBuiltWhileVciIsOff(): void
    {
        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciEnabled')->willReturn(false);
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with('Verifiable Credential capabilities not enabled.');

        try {
            new CredentialJsonLdContextController($moduleConfig, $this->routesMock, $this->loggerServiceMock);
            $this->fail('No refusal.');
        } catch (OidcServerException $exception) {
            $this->assertSame(403, $exception->getHttpStatusCode());
            $this->assertSame('forbidden', $exception->getErrorType());
            $this->assertSame('Verifiable Credential capabilities not enabled.', $exception->getHint());
        }
    }


    public function testServesTheConfiguredContextDocumentAsJsonLd(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getVciCredentialJsonLdContextFor')
            ->with(self::CREDENTIAL_CONFIGURATION_ID)
            ->willReturn(self::CONTEXT_DOCUMENT);
        $this->loggerServiceMock->expects($this->once())
            ->method('debug')
            ->with(
                'CredentialJsonLdContextController::context',
                ['credentialConfigurationId' => self::CREDENTIAL_CONFIGURATION_ID],
            );
        $this->loggerServiceMock->expects($this->never())->method('warning');
        $response = new JsonResponse(self::CONTEXT_DOCUMENT);
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with(self::CONTEXT_DOCUMENT, Response::HTTP_OK, ['Content-Type' => 'application/ld+json'])
            ->willReturn($response);
        $this->routesMock->expects($this->never())->method('newResponse');

        $this->assertSame($response, $this->sut()->context(self::CREDENTIAL_CONFIGURATION_ID));
    }


    public function testAnswersNotFoundWithNoBodyForAConfigurationWithoutAContextDocument(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getVciCredentialJsonLdContextFor')
            ->with(self::CREDENTIAL_CONFIGURATION_ID)
            ->willReturn(null);
        $this->loggerServiceMock->expects($this->once())
            ->method('warning')
            ->with(
                'CredentialJsonLdContextController::context: No JSON-LD context configured for credential ' .
                'configuration ID.',
                ['credentialConfigurationId' => self::CREDENTIAL_CONFIGURATION_ID],
            );
        $response = new Response(null, Response::HTTP_NOT_FOUND);
        $this->routesMock->expects($this->once())
            ->method('newResponse')
            ->with($this->identicalTo(null), Response::HTTP_NOT_FOUND)
            ->willReturn($response);
        $this->routesMock->expects($this->never())->method('newJsonResponse');

        $this->assertSame($response, $this->sut()->context(self::CREDENTIAL_CONFIGURATION_ID));
    }
}
