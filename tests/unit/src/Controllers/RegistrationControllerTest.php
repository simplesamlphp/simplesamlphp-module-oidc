<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\DcrRegistrationAuthEnum;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
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
use SimpleSAML\OpenID\Network\DestinationPolicy;
use Stringable;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(RegistrationController::class)]
#[UsesClass(ClientMetadataValidator::class)]
#[UsesClass(OidcServerException::class)]
#[UsesClass(ErrorResponder::class)]
#[UsesClass(Helpers::class)]
#[AllowMockObjectsWithoutExpectations]
class RegistrationControllerTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $clientEntityFactoryMock;

    protected MockObject $clientRepositoryMock;

    protected MockObject $routesMock;

    protected MockObject $loggerMock;

    protected MockObject $clientMock;

    protected ClientMetadataValidator $clientMetadataValidator;

    protected ErrorResponder $errorResponder;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDcrEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getDcrRegistrationAuth')->willReturn(DcrRegistrationAuthEnum::Open);
        $this->moduleConfigMock->method('getDcrImpersonationProtectionEnabled')->willReturn(true);

        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('getModuleUrl')
            ->willReturn('https://op.example.org/oidc/register?client_id=client123');
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            fn(?array $data = null, int $status = 200, array $headers = [], bool $json = false): JsonResponse =>
                new JsonResponse($data, $status, $headers, $json),
        );
        $this->routesMock->method('newResponse')->willReturnCallback(
            fn(?string $content = '', int $status = 200, array $headers = []): Response =>
                new Response((string)$content, $status, $headers),
        );

        $this->loggerMock = $this->createMock(LoggerService::class);

        // ErrorResponder::forExceptionJson builds the JSON response itself and does not use the bridge.
        $this->errorResponder = new ErrorResponder($this->createMock(PsrHttpBridge::class), $this->loggerMock);
        // A real policy with the sample client host exempted, so these tests resolve nothing while still
        // running the registration path that the policy is part of.
        $this->clientMetadataValidator = new ClientMetadataValidator(
            $this->moduleConfigMock,
            new DestinationPolicy(allowedHosts: ['client.example.org', 'op.example.org']),
        );
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
            $this->errorResponder,
            $this->helpers,
            $this->routesMock,
            $this->loggerMock,
        );
    }


    protected function postRequest(string $json, ?string $authorization = null): Request
    {
        $request = Request::create(
            'https://op.example.org/oidc/register',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            $json,
        );
        if ($authorization !== null) {
            $request->headers->set('Authorization', $authorization);
        }

        return $request;
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
        $moduleConfigMock->method('getDcrEnabled')->willReturn(false);
        $this->moduleConfigMock = $moduleConfigMock;

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

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


    public function testWrongContentTypeReturns400InvalidRequest(): void
    {
        $request = Request::create(
            'https://op.example.org/oidc/register',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'text/plain'],
            '{"redirect_uris":["https://client.example.org/cb"]}',
        );

        $response = $this->sut()->registration($request);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->decode($response)['error']);
    }


    public function testJsonContentTypeWithCharsetParameterIsAccepted(): void
    {
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);

        $request = Request::create(
            'https://op.example.org/oidc/register',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json; charset=utf-8'],
            '{"redirect_uris":["https://client.example.org/cb"]}',
        );

        $response = $this->sut()->registration($request);

        $this->assertSame(201, $response->getStatusCode());
    }


    public function testInitialAccessTokenModeRejectsMissingToken(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDcrEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getDcrRegistrationAuth')
            ->willReturn(DcrRegistrationAuthEnum::InitialAccessToken);
        $this->moduleConfigMock->method('getDcrInitialAccessTokens')->willReturn(['secret-iat']);

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

        // RFC 7592 Section 3: a read rotates the RAT - a new hash is persisted and the new plaintext returned.
        $this->clientMock->expects($this->once())->method('setRegistrationAccessTokenHash');
        $this->clientRepositoryMock->expects($this->once())->method('update');

        $request = Request::create('https://op.example.org/oidc/register?client_id=client123', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $response = $this->sut()->registration($request);

        $this->assertSame(200, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertSame('client123', $body['client_id']);
        $this->assertArrayHasKey('registration_access_token', $body);
        $this->assertArrayHasKey('registration_client_uri', $body);
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


    /**
     * A request to the Client Configuration Endpoint (read, update, delete) as a caller holding the token of
     * givenAFindableClient() would send it. Either credential can be left out to make the request incomplete.
     * The body is metadata the validator accepts, so that a refusal is the authentication's own.
     */
    protected function configurationRequest(
        string $method,
        ?string $clientId = 'client123',
        ?string $authorization = 'Bearer rat-plaintext',
        string $body = '{"redirect_uris":["https://client.example.org/cb"]}',
    ): Request {
        $uri = 'https://op.example.org/oidc/register' . ($clientId === null ? '' : '?client_id=' . $clientId);
        $request = Request::create($uri, $method, [], [], [], ['CONTENT_TYPE' => 'application/json'], $body);
        if ($authorization !== null) {
            $request->headers->set('Authorization', $authorization);
        }

        return $request;
    }


    /**
     * Have the repository find the client of setUp() under its identifier and nothing under any other, the
     * client being registered the given way and holding the hash of the given token, or no hash at all.
     */
    protected function givenAFindableClient(
        RegistrationTypeEnum $registrationType = RegistrationTypeEnum::Dynamic,
        ?string $tokenHeld = 'rat-plaintext',
    ): void {
        $this->clientMock->method('getRegistrationType')->willReturn($registrationType);
        $this->clientMock->method('getRegistrationAccessTokenHash')
            ->willReturn($tokenHeld === null ? null : hash('sha256', $tokenHeld));
        $this->clientRepositoryMock->method('findById')->willReturnCallback(
            fn(string $clientId): ?ClientEntityInterface => $clientId === 'client123' ? $this->clientMock : null,
        );
    }


    /**
     * A module configuration which demands an Initial Access Token and accepts the given ones.
     */
    protected function requireAnInitialAccessToken(array $acceptedTokens): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getDcrEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getDcrRegistrationAuth')
            ->willReturn(DcrRegistrationAuthEnum::InitialAccessToken);
        $this->moduleConfigMock->method('getDcrInitialAccessTokens')->willReturn($acceptedTokens);
    }


    /**
     * Refuse every write: no client built from metadata, none added, updated or removed, and no token hash
     * set on the client found.
     */
    protected function expectNothingWritten(): void
    {
        $this->clientEntityFactoryMock->expects($this->never())->method('fromRegistrationData');
        $this->clientRepositoryMock->expects($this->never())->method('add');
        $this->clientRepositoryMock->expects($this->never())->method('update');
        $this->clientRepositoryMock->expects($this->never())->method('delete');
        $this->clientMock->expects($this->never())->method('setRegistrationAccessTokenHash');
    }


    /**
     * Put a validator in place of the real one which expects to be told, once, whether the caller is
     * authenticated, and hands the metadata back as the real one does on success.
     */
    protected function expectTheValidatorToBeToldTheCallerIsAuthenticated(bool $isAuthenticated): void
    {
        $validator = $this->createMock(ClientMetadataValidator::class);
        $validator->expects($this->once())->method('validate')
            ->with(['redirect_uris' => ['https://client.example.org/cb']], $isAuthenticated)
            ->willReturnArgument(0);
        $this->clientMetadataValidator = $validator;
    }


    /**
     * A client answering the getters the Client Information Response is built from: the required ones as
     * given here, the optional ones as the caller says.
     *
     * @param array<string,mixed> $getters
     */
    protected function clientAnswering(array $getters): ClientEntityInterface&MockObject
    {
        $answers = array_merge([
            'getIdentifier' => 'client123',
            'getCreatedAt' => new DateTimeImmutable('2026-06-24T00:00:00', new DateTimeZone('UTC')),
            'getRedirectUris' => ['https://client.example.org/cb'],
            'getName' => 'Example',
            'getScopes' => ['openid', 'profile'],
            'getGrantTypes' => ['authorization_code', 'refresh_token'],
            'getResponseTypes' => ['code'],
            'getTokenEndpointAuthMethod' => 'client_secret_basic',
        ], $getters);

        $client = $this->createMock(ClientEntityInterface::class);
        foreach ($answers as $getter => $value) {
            $client->method($getter)->willReturn($value);
        }

        return $client;
    }


    #[DataProvider('unservedMethodProvider')]
    public function testAnswersAMethodItDoesNotServeWith405NamingTheOnesItDoes(string $method): void
    {
        $this->clientRepositoryMock->expects($this->never())->method('findById');
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->configurationRequest($method));

        $this->assertSame(405, $response->getStatusCode());
        $this->assertSame('GET, POST, PUT, DELETE', $response->headers->get('Allow'));
        $this->assertSame('', $response->getContent());
    }


    public static function unservedMethodProvider(): array
    {
        return [
            'PATCH' => ['PATCH'],
            'HEAD' => ['HEAD'],
            'OPTIONS' => ['OPTIONS'],
        ];
    }


    public function testAnUnexpectedFailureBecomesAServerErrorWhichKeepsItsCauseForTheLog(): void
    {
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);
        $this->clientRepositoryMock->method('add')
            ->willThrowException(new RuntimeException('SQLSTATE[HY000]: db.internal is unreachable'));
        $logged = [];
        $this->loggerMock->method('error')->willReturnCallback(
            function (string|Stringable $message) use (&$logged): void {
                $logged[] = (string)$message;
            },
        );

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $this->assertSame(500, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertSame('server_error', $body['error']);
        $this->assertStringEndsWith('Unable to process the registration request.', $body['error_description']);
        // Status line, headers and body alike.
        $this->assertStringNotContainsString('db.internal', (string)$response);
        $this->assertNotEmpty(
            array_filter($logged, static fn(string $message): bool => str_contains($message, 'db.internal')),
        );
    }


    public function testReturnsTheRegistrationAccessTokenWhoseHashItStoresAndForbidsCachingIt(): void
    {
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);
        $storedHash = null;
        $this->clientMock->expects($this->once())->method('setRegistrationAccessTokenHash')
            ->willReturnCallback(function (?string $hash) use (&$storedHash): void {
                $storedHash = $hash;
            });

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $token = $this->decode($response)['registration_access_token'];
        $this->assertIsString($token);
        $this->assertNotSame('', $token);
        $this->assertSame(hash('sha256', $token), $storedHash);
        $this->assertTrue($response->headers->hasCacheControlDirective('no-store'));
        $this->assertSame('no-cache', $response->headers->get('Pragma'));
    }


    public function testAnswersWithEveryOptionalValueTheClientCarriesAndOnlyThose(): void
    {
        $client = $this->clientAnswering([
            'isConfidential' => true,
            'getSecret' => 'the-secret',
            'getIdTokenSignedResponseAlg' => 'RS256',
            'getRequestUris' => ['https://client.example.org/request.jwt'],
            'getDefaultMaxAge' => 3600,
            'getRequireAuthTime' => true,
            'getDefaultAcrValues' => ['urn:mace:incommon:iap:silver'],
            'getExtraMetadata' => [
                'logo_uri' => 'https://client.example.org/logo.png',
                'client_uri' => 'https://client.example.org/',
                'policy_uri' => 'https://client.example.org/policy',
                'tos_uri' => 'https://client.example.org/tos',
                'contacts' => ['admin@client.example.org'],
                'application_type' => 'web',
                'initiate_login_uri' => 'https://client.example.org/login',
                'software_id' => 'example-client',
                'software_version' => '1.2.3',
                // Stored, but not among what is echoed.
                'internal_note' => 'never echoed',
            ],
        ]);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($client);
        $this->routesMock->expects($this->once())->method('getModuleUrl')
            ->with(RoutesEnum::Registration->value, ['client_id' => 'client123']);

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $this->assertSame(201, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertArrayHasKey('registration_access_token', $body);
        unset($body['registration_access_token']);
        $expected = [
            'client_id' => 'client123',
            'client_id_issued_at' => 1782259200,
            'registration_client_uri' => 'https://op.example.org/oidc/register?client_id=client123',
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_name' => 'Example',
            'scope' => 'openid profile',
            'client_secret' => 'the-secret',
            'client_secret_expires_at' => 0,
            'id_token_signed_response_alg' => 'RS256',
            'request_uris' => ['https://client.example.org/request.jwt'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'default_max_age' => 3600,
            'require_auth_time' => true,
            'default_acr_values' => ['urn:mace:incommon:iap:silver'],
            'logo_uri' => 'https://client.example.org/logo.png',
            'client_uri' => 'https://client.example.org/',
            'policy_uri' => 'https://client.example.org/policy',
            'tos_uri' => 'https://client.example.org/tos',
            'contacts' => ['admin@client.example.org'],
            'application_type' => 'web',
            'initiate_login_uri' => 'https://client.example.org/login',
            'software_id' => 'example-client',
            'software_version' => '1.2.3',
        ];
        ksort($expected);
        ksort($body);
        $this->assertSame($expected, $body);
    }


    public function testAnswersWithNoOptionalValueForAPublicClientCarryingNone(): void
    {
        $client = $this->clientAnswering([
            'isConfidential' => false,
            'getTokenEndpointAuthMethod' => 'none',
            'getIdTokenSignedResponseAlg' => null,
            'getRequestUris' => [],
            'getDefaultMaxAge' => null,
            'getRequireAuthTime' => false,
            'getDefaultAcrValues' => [],
            'getExtraMetadata' => [],
        ]);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($client);

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $this->assertSame(201, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertArrayHasKey('registration_access_token', $body);
        unset($body['registration_access_token']);
        $expected = [
            'client_id' => 'client123',
            'client_id_issued_at' => 1782259200,
            'registration_client_uri' => 'https://op.example.org/oidc/register?client_id=client123',
            'redirect_uris' => ['https://client.example.org/cb'],
            'client_name' => 'Example',
            'scope' => 'openid profile',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];
        ksort($expected);
        ksort($body);
        $this->assertSame($expected, $body);
    }


    #[DataProvider('jsonWhichIsNotAnObjectProvider')]
    public function testRefusesABodyWhichIsJsonButNotAnObject(string $body): void
    {
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->postRequest($body));

        $this->assertSame(400, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('invalid_client_metadata', $decoded['error']);
        $this->assertSame('The request body must be a JSON object.', $decoded['hint']);
    }


    public static function jsonWhichIsNotAnObjectProvider(): array
    {
        return [
            'an empty list' => ['[]'],
            'a list' => ['["https://client.example.org/cb"]'],
            'a string' => ['"redirect_uris"'],
            'null' => ['null'],
        ];
    }


    #[DataProvider('configuredInitialAccessTokenProvider')]
    public function testAcceptsAnyOneOfTheConfiguredInitialAccessTokens(string $presented): void
    {
        $this->requireAnInitialAccessToken(['first-iat', 'second-iat', 'third-iat']);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);
        $this->clientRepositoryMock->expects($this->once())->method('add');

        $response = $this->sut()->registration($this->postRequest(
            '{"redirect_uris":["https://client.example.org/cb"]}',
            'Bearer ' . $presented,
        ));

        $this->assertSame(201, $response->getStatusCode());
    }


    public static function configuredInitialAccessTokenProvider(): array
    {
        return [
            'the first' => ['first-iat'],
            'one in the middle' => ['second-iat'],
            'the last' => ['third-iat'],
        ];
    }


    #[DataProvider('unacceptableInitialAccessTokenProvider')]
    public function testRefusesAnInitialAccessTokenOtherThanAConfiguredOne(array $configured, string $presented): void
    {
        $this->requireAnInitialAccessToken($configured);
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->postRequest(
            '{"redirect_uris":["https://client.example.org/cb"]}',
            'Bearer ' . $presented,
        ));

        $this->assertSame(401, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('access_denied', $decoded['error']);
        $this->assertSame('The provided Initial Access Token is not valid.', $decoded['hint']);
    }


    public static function unacceptableInitialAccessTokenProvider(): array
    {
        return [
            'none is configured' => [[], 'secret-iat'],
            'another than those configured' => [['first-iat', 'second-iat'], 'third-iat'],
            'a prefix of a configured one' => [['secret-iat'], 'secret'],
            'a configured one with more appended' => [['secret-iat'], 'secret-iat-and-more'],
            'a configured one in another case' => [['secret-iat'], 'SECRET-IAT'],
        ];
    }


    /**
     * The validator runs its destination checks only for a caller who has proven an identity, and the
     * controller is what tells it whether this one has. Under open registration nobody has.
     */
    public function testUnderOpenRegistrationTheMetadataIsValidatedAsFromACallerWithNoIdentity(): void
    {
        $this->expectTheValidatorToBeToldTheCallerIsAuthenticated(false);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);

        $response = $this->sut()->registration(
            $this->postRequest('{"redirect_uris":["https://client.example.org/cb"]}'),
        );

        $this->assertSame(201, $response->getStatusCode());
    }


    public function testUnderAnInitialAccessTokenTheMetadataIsValidatedAsFromAnAuthenticatedCaller(): void
    {
        $this->requireAnInitialAccessToken(['secret-iat']);
        $this->expectTheValidatorToBeToldTheCallerIsAuthenticated(true);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);

        $response = $this->sut()->registration($this->postRequest(
            '{"redirect_uris":["https://client.example.org/cb"]}',
            'Bearer secret-iat',
        ));

        $this->assertSame(201, $response->getStatusCode());
    }


    public function testOnUpdateTheMetadataIsValidatedAsFromAnAuthenticatedCaller(): void
    {
        $this->givenAFindableClient();
        $this->expectTheValidatorToBeToldTheCallerIsAuthenticated(true);
        $this->clientEntityFactoryMock->method('fromRegistrationData')->willReturn($this->clientMock);

        $response = $this->sut()->registration($this->configurationRequest('PUT'));

        $this->assertSame(200, $response->getStatusCode());
    }


    #[DataProvider('incompleteConfigurationRequestProvider')]
    public function testRefusesAnIncompleteConfigurationRequestWithoutLookingAnythingUp(
        string $method,
        ?string $clientId,
        ?string $authorization,
    ): void {
        $this->clientRepositoryMock->expects($this->never())->method('findById');
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->configurationRequest($method, $clientId, $authorization));

        $this->assertSame(401, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('access_denied', $decoded['error']);
        $this->assertSame('A valid client_id and Registration Access Token are required.', $decoded['hint']);
    }


    public static function incompleteConfigurationRequestProvider(): iterable
    {
        $shapes = [
            'no client_id' => [null, 'Bearer rat-plaintext'],
            'an empty client_id' => ['', 'Bearer rat-plaintext'],
            'no Authorization header' => ['client123', null],
            'a scheme other than Bearer' => ['client123', 'Basic Y2xpZW50MTIzOnJhdC1wbGFpbnRleHQ='],
            'a Bearer scheme with no token' => ['client123', 'Bearer '],
        ];

        foreach (['GET', 'PUT', 'DELETE'] as $method) {
            foreach ($shapes as $shape => [$clientId, $authorization]) {
                yield sprintf('%s with %s', $method, $shape) => [$method, $clientId, $authorization];
            }
        }
    }


    #[DataProvider('clientWhichCannotBeConfiguredProvider')]
    public function testRefusesAConfigurationRequestForAClientWhichCannotBeConfigured(
        string $method,
        RegistrationTypeEnum $registrationType,
        ?string $tokenHeld,
    ): void {
        $this->givenAFindableClient($registrationType, $tokenHeld);
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->configurationRequest($method));

        $this->assertSame(401, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('access_denied', $decoded['error']);
        $this->assertSame('Invalid Registration Access Token.', $decoded['hint']);
    }


    public static function clientWhichCannotBeConfiguredProvider(): iterable
    {
        $clients = [
            'a manually registered client, even one holding the token presented' => [
                RegistrationTypeEnum::Manual,
                'rat-plaintext',
            ],
            'a federation-registered client, even one holding the token presented' => [
                RegistrationTypeEnum::FederatedAutomatic,
                'rat-plaintext',
            ],
            'a dynamically registered client holding no token' => [RegistrationTypeEnum::Dynamic, null],
        ];

        foreach (['GET', 'PUT', 'DELETE'] as $method) {
            foreach ($clients as $client => [$registrationType, $tokenHeld]) {
                yield sprintf('%s of %s', $method, $client) => [$method, $registrationType, $tokenHeld];
            }
        }
    }


    /**
     * Never revealing whether a client exists (the class cites Section 4.4 for it) means the answer to an
     * unknown client is the answer to a wrong token.
     */
    #[DataProvider('configurationMethodProvider')]
    public function testDoesNotRevealWhetherAClientExists(string $method): void
    {
        $this->givenAFindableClient();
        $this->expectNothingWritten();

        $forAClientWhichDoesNotExist = $this->sut()->registration(
            $this->configurationRequest($method, 'no-such-client', 'Bearer rat-plaintext'),
        );
        $forAWrongToken = $this->sut()->registration(
            $this->configurationRequest($method, 'client123', 'Bearer wrong-token'),
        );

        $this->assertSame(401, $forAClientWhichDoesNotExist->getStatusCode());
        $this->assertSame(
            'Invalid Registration Access Token.',
            $this->decode($forAClientWhichDoesNotExist)['hint'],
        );
        $this->assertSame($forAClientWhichDoesNotExist->getStatusCode(), $forAWrongToken->getStatusCode());
        $this->assertSame($forAClientWhichDoesNotExist->getContent(), $forAWrongToken->getContent());
    }


    public static function configurationMethodProvider(): array
    {
        return [
            'read' => ['GET'],
            'update' => ['PUT'],
            'delete' => ['DELETE'],
        ];
    }


    public function testUpdateReplacesTheMetadataRotatesTheTokenAndAnswersWithTheClientAsItNowIs(): void
    {
        $this->givenAFindableClient();
        $updatedClient = $this->clientAnswering([
            'isConfidential' => false,
            'getTokenEndpointAuthMethod' => 'none',
            'getRedirectUris' => ['https://client.example.org/new-cb'],
            'getName' => 'Renamed',
        ]);
        $this->clientEntityFactoryMock->expects($this->once())->method('fromRegistrationData')
            ->with(
                ['redirect_uris' => ['https://client.example.org/new-cb'], 'client_name' => 'Renamed'],
                RegistrationTypeEnum::Dynamic,
                null,
                $this->identicalTo($this->clientMock),
            )
            ->willReturn($updatedClient);
        // The token is rotated on the client which is persisted, and on that one only.
        $storedHash = null;
        $updatedClient->expects($this->once())->method('setRegistrationAccessTokenHash')
            ->willReturnCallback(function (?string $hash) use (&$storedHash): void {
                $storedHash = $hash;
            });
        $this->clientMock->expects($this->never())->method('setRegistrationAccessTokenHash');
        $this->clientRepositoryMock->expects($this->once())->method('update')
            ->with($this->identicalTo($updatedClient));
        $this->clientRepositoryMock->expects($this->never())->method('add');
        $this->clientRepositoryMock->expects($this->never())->method('delete');

        $response = $this->sut()->registration($this->configurationRequest(
            'PUT',
            body: '{"redirect_uris":["https://client.example.org/new-cb"],"client_name":"Renamed"}',
        ));

        $this->assertSame(200, $response->getStatusCode());
        $body = $this->decode($response);
        $this->assertSame(hash('sha256', $body['registration_access_token']), $storedHash);
        unset($body['registration_access_token']);
        $expected = [
            'client_id' => 'client123',
            'client_id_issued_at' => 1782259200,
            'registration_client_uri' => 'https://op.example.org/oidc/register?client_id=client123',
            'redirect_uris' => ['https://client.example.org/new-cb'],
            'client_name' => 'Renamed',
            'scope' => 'openid profile',
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
        ];
        ksort($expected);
        ksort($body);
        $this->assertSame($expected, $body);
    }


    public function testUpdateRefusesABodyNamingAnotherClient(): void
    {
        $this->givenAFindableClient();
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->configurationRequest(
            'PUT',
            body: '{"redirect_uris":["https://client.example.org/cb"],"client_id":"someone-else"}',
        ));

        $this->assertSame(400, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('invalid_client_metadata', $decoded['error']);
        $this->assertSame('The client_id must match the client being updated.', $decoded['hint']);
    }


    public function testUpdateRefusesABodyCarryingAnotherSecret(): void
    {
        $this->givenAFindableClient();
        $this->expectNothingWritten();

        $response = $this->sut()->registration($this->configurationRequest(
            'PUT',
            body: '{"redirect_uris":["https://client.example.org/cb"],"client_secret":"not-the-secret"}',
        ));

        $this->assertSame(400, $response->getStatusCode());
        $decoded = $this->decode($response);
        $this->assertSame('invalid_client_metadata', $decoded['error']);
        $this->assertSame('The client_secret must match the client being updated.', $decoded['hint']);
    }


    public function testUpdateAcceptsTheClientsOwnCredentialsInTheBodyAndDropsTheSecretBeforeGoingOn(): void
    {
        $this->givenAFindableClient();
        $this->clientEntityFactoryMock->expects($this->once())->method('fromRegistrationData')
            ->with(
                ['redirect_uris' => ['https://client.example.org/cb'], 'client_id' => 'client123'],
                RegistrationTypeEnum::Dynamic,
                null,
                $this->identicalTo($this->clientMock),
            )
            ->willReturn($this->clientMock);

        $response = $this->sut()->registration($this->configurationRequest(
            'PUT',
            body: '{"redirect_uris":["https://client.example.org/cb"],'
                . '"client_id":"client123","client_secret":"the-secret"}',
        ));

        $this->assertSame(200, $response->getStatusCode());
    }


    public function testAFailedUpdateLeavesTheClientAndItsTokenAsTheyWere(): void
    {
        $this->givenAFindableClient();
        $this->expectNothingWritten();

        $response = $this->sut()->registration(
            $this->configurationRequest('PUT', body: '{"client_name":"Without redirect URIs"}'),
        );

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_redirect_uri', $this->decode($response)['error']);
    }


    public function testUpdateAuthenticatesTheCallerBeforeReadingTheBody(): void
    {
        $this->givenAFindableClient();
        $this->expectNothingWritten();

        $response = $this->sut()->registration(
            $this->configurationRequest('PUT', authorization: 'Bearer wrong-token', body: 'not-json'),
        );

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('access_denied', $this->decode($response)['error']);
    }


    public function testDeleteRemovesTheClientAndAnswersWithNoContent(): void
    {
        $this->givenAFindableClient();
        $this->clientRepositoryMock->expects($this->once())->method('delete')
            ->with($this->identicalTo($this->clientMock));
        $this->clientRepositoryMock->expects($this->never())->method('update');
        $this->clientRepositoryMock->expects($this->never())->method('add');
        // Nothing is rotated on the way out.
        $this->clientMock->expects($this->never())->method('setRegistrationAccessTokenHash');

        $response = $this->sut()->registration($this->configurationRequest('DELETE'));

        $this->assertSame(204, $response->getStatusCode());
        $this->assertSame('', $response->getContent());
    }
}
