<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
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
     * Served with 200 as an unsigned JSON document, its media type stated in the Content-Type header (OpenID4VCI
     * 1.0 section 12.2.2), whatever the wallet's Accept header asks for. That is the only type offered, signed
     * metadata not being supported: a wallet asking for `application/json` gets it, and one asking for
     * `application/jwt` alone gets it too, which the section allows (the response matches the Accept header where
     * the type asked for is supported). The header is set where a request built from the globals reads it, and the
     * endpoint takes no request through which it could be handed another.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     * @throws \ReflectionException
     */
    #[DataProvider('acceptHeaderProvider')]
    public function testServesTheDocumentAsUnsignedJsonWithStatus200(?string $accept): void
    {
        $hadAccept = array_key_exists('HTTP_ACCEPT', $_SERVER);
        /** @psalm-suppress MixedAssignment */
        $previousAccept = $_SERVER['HTTP_ACCEPT'] ?? null;
        if ($accept === null) {
            unset($_SERVER['HTTP_ACCEPT']);
        } else {
            $_SERVER['HTTP_ACCEPT'] = $accept;
        }

        try {
            $response = (new CredentialIssuerConfigurationController(
                $this->moduleConfigMock,
                new Routes($this->createStub(ModuleConfig::class), $this->createStub(SspBridge::class)),
                $this->loggerServiceMock,
                $this->credentialIssuerMetadataServiceMock,
            ))->configuration();
        } finally {
            if ($hadAccept) {
                /** @psalm-suppress MixedAssignment */
                $_SERVER['HTTP_ACCEPT'] = $previousAccept;
            } else {
                unset($_SERVER['HTTP_ACCEPT']);
            }
        }

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertSame(
            self::METADATA,
            json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR),
        );
        $this->assertSame(
            0,
            (new ReflectionMethod(CredentialIssuerConfigurationController::class, 'configuration'))
                ->getNumberOfParameters(),
        );
    }


    /**
     * @return array<string,array{0: ?string}>
     */
    public static function acceptHeaderProvider(): array
    {
        return [
            'no Accept header' => [null],
            'application/json' => ['application/json'],
            'application/jwt alone' => ['application/jwt'],
            'application/jwt preferred' => ['application/jwt, application/json;q=0.5'],
            'any type' => ['*/*'],
        ];
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
