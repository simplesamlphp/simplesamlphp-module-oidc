<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Laminas\Diactoros\StreamFactory;
use Laminas\Diactoros\UploadedFileFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Controllers\RegistrationController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Registration\ClientMetadataValidator;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(RegistrationController::class)]
#[UsesClass(ClientMetadataValidator::class)]
#[UsesClass(OidcServerException::class)]
#[UsesClass(ErrorResponder::class)]
#[UsesClass(PsrHttpBridge::class)]
class RegistrationControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;
    protected MockObject $clientEntityFactoryMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $routesMock;
    protected MockObject $loggerMock;
    protected MockObject $clientMock;
    protected PsrHttpBridge $psrHttpBridge;
    protected ClientMetadataValidator $clientMetadataValidator;
    protected ErrorResponder $errorResponder;
    protected Helpers $helpers;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getOidcDcrEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getOidcDcrRegistrationAuth')->willReturn(DcrRegistrationAuthEnum::Open);
        $this->moduleConfigMock->method('getOidcDcrImpersonationProtectionEnabled')->willReturn(true);

        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('getModuleUrl')
            ->willReturn('https://op.example.org/oidc/register?client_id=client123');
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->psrHttpBridge = new PsrHttpBridge(
            new HttpFoundationFactory(),
            new ServerRequestFactory(),
            new ResponseFactory(),
            new StreamFactory(),
            new UploadedFileFactory(),
        );
        $this->clientMetadataValidator = new ClientMetadataValidator($this->moduleConfigMock);
        $this->errorResponder = new ErrorResponder($this->psrHttpBridge);
        $this->helpers = new Helpers();

        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn('client123');
        $this->clientMock->method('getCreatedAt')
            ->willReturn(new DateTimeImmutable('2026-06-24T00:00:00', new DateTimeZone('UTC')));
        $this->clientMock->method('getRedirectUris')->willReturn(['https://client.example.org/cb']);
        $this->clientMock->method('getName')->willReturn('Example');
        $this->clientMock->method('getScopes')->willReturn(['openid']);
        $this->clientMock->method('isConfidential')->willReturn(true);
        $this->clientMock->method('getSecret')->willReturn('the-secret');
        $this->clientMock->method('getIdTokenSignedResponseAlg')->willReturn(null);
        $this->clientMock->method('getExtraMetadata')->willReturn([]);
    }

    protected function sut(): RegistrationController
    {
        return new RegistrationController(
            $this->moduleConfigMock,
            $this->clientMetadataValidator,
            $this->clientEntityFactoryMock,
            $this->clientRepositoryMock,
            $this->psrHttpBridge,
            $this->errorResponder,
            $this->helpers,
            $this->routesMock,
            $this->loggerMock,
        );
    }

    protected function postRequest(string $json): Request
    {
        return Request::create(
            'https://op.example.org/oidc/register',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            $json,
        );
    }

    /**
     * @return array
     */
    protected function decode(Response $response): array
    {
        /** @var array $decoded */
        $decoded = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    public function testCreateReturns201WithClientIdAndRegistrationAccessToken(): void
    {
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);
        $this->clientMock->expects($this->once())->method('setRegistrationAccessTokenHash');
        $this->clientRepositoryMock->expects($this->once())->method('add')->with($this->clientMock);

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"],"client_name":"Example"}'),
        );

        $this->assertSame(201, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertSame('client123', $body['client_id']);
        $this->assertArrayHasKey('registration_access_token', $body);
        $this->assertArrayHasKey('registration_client_uri', $body);
        $this->assertSame('the-secret', $body['client_secret']);
        $this->assertSame(0, $body['client_secret_expires_at']);
    }

    public function testDisabledFeatureReturns404(): void
    {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getOidcDcrEnabled')->willReturn(false);
        $this->moduleConfigMock = $moduleConfigMock;

        $response = $this->sut()->registration($this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'));

        $this->assertSame(404, $response->getStatusCode());
    }

    public function testMissingRedirectUrisReturns400InvalidRedirectUri(): void
    {
        $response = $this->sut()->registration($this->postRequest('{"client_name":"Example"}'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_redirect_uri', $this->decode($response)['error']);
    }

    public function testInvalidJsonReturns400InvalidClientMetadata(): void
    {
        $response = $this->sut()->registration($this->postRequest('not-json'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_client_metadata', $this->decode($response)['error']);
    }

    public function testInitialAccessTokenModeRejectsMissingToken(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getOidcDcrEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getOidcDcrRegistrationAuth')
            ->willReturn(DcrRegistrationAuthEnum::InitialAccessToken);
        $this->moduleConfigMock->method('getOidcDcrInitialAccessTokens')->willReturn(['secret-iat']);

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReadReturns200ForValidToken(): void
    {
        $token = 'rat-plaintext';
        $this->clientMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Dynamic);
        $this->clientMock->method('getRegistrationAccessTokenHash')->willReturn(hash('sha256', $token));
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientMock);

        $request = Request::create('https://op.example.org/oidc/register?client_id=client123', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $response = $this->sut()->registration($request);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('client123', $this->decode($response)['client_id']);
    }

    public function testReadReturns401ForInvalidToken(): void
    {
        $this->clientMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Dynamic);
        $this->clientMock->method('getRegistrationAccessTokenHash')->willReturn(hash('sha256', 'correct-token'));
        $this->clientRepositoryMock->method('findById')->willReturn($this->clientMock);

        $request = Request::create('https://op.example.org/oidc/register?client_id=client123', 'GET');
        $request->headers->set('Authorization', 'Bearer wrong-token');

        $response = $this->sut()->registration($request);

        $this->assertSame(401, $response->getStatusCode());
    }

    public function testReadReturns401ForUnknownClient(): void
    {
        $this->clientRepositoryMock->method('findById')->willReturn(null);

        $request = Request::create('https://op.example.org/oidc/register?client_id=missing', 'GET');
        $request->headers->set('Authorization', 'Bearer any-token');

        $response = $this->sut()->registration($request);

        $this->assertSame(401, $response->getStatusCode());
    }
}
