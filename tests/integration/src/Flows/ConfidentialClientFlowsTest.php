<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Flows;

use DateTimeImmutable;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Container;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;

class ConfidentialClientFlowsTest extends TestCase
{
    protected Container $container;
    protected ClientRepository $clientRepo;
    protected UserRepository $userRepo;
    protected ClientEntityFactory $clientFactory;
    protected AuthorizationServer $authServer;

    protected string $clientId = 'confidential-flow-test-client';
    protected string $clientSecret = 'my-super-secret-key-12345';
    protected string $redirectUri = 'https://oidcdebugger.com/debug';
    protected string $userId = 'test-flow-user';

    protected ClientEntity $client;
    protected UserEntity $user;
    protected array $originalServer;
    protected Configuration $originalModuleConfig;

    public static function setUpBeforeClass(): void
    {
        Configuration::setConfigDir(__DIR__ . '/../../../config');
        $config = Configuration::getConfig('config.php')->toArray();
        $config['database.dsn'] = 'sqlite::memory:';
        $config['database.username'] = null;
        $config['database.password'] = null;
        $config['database.prefix'] = 'phpunit_';
        $config['database.persistent'] = true;
        $config['database.secondaries'] = [];

        Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }

    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['REQUEST_URI'] = '/module.php/oidc/authorization';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        Configuration::setConfigDir(__DIR__ . '/../../../config');
        $this->originalModuleConfig = Configuration::getConfig(ModuleConfig::DEFAULT_FILE_NAME);
        // Enable the opt-in hardening for these tests.
        $this->buildContainer(disallowImplicitForConfidentialClients: true);

        // Set up test user
        $this->user = new UserEntity(
            $this->userId,
            new DateTimeImmutable(),
            new DateTimeImmutable(),
            ['sub' => $this->userId, 'eduPersonPrincipalName' => [$this->userId]]
        );
        $existingUser = $this->userRepo->getUserEntityByIdentifier($this->userId);
        if ($existingUser) {
            $this->userRepo->delete($existingUser);
        }
        $this->userRepo->add($this->user);

        // Set up confidential client
        $existingClient = $this->clientRepo->findById($this->clientId);
        if ($existingClient) {
            $this->clientRepo->delete($existingClient);
        }

        $this->client = $this->clientFactory->fromData(
            id: $this->clientId,
            secret: $this->clientSecret,
            name: 'Confidential Flow Test Client',
            description: 'Testing confidential client flows and implicit grant restriction',
            redirectUri: [$this->redirectUri],
            scopes: ['openid', 'profile', 'email'],
            isEnabled: true,
            isConfidential: true, // CONFIDENTIAL CLIENT
        );
        $this->clientRepo->add($this->client);
    }

    protected function buildContainer(bool $disallowImplicitForConfidentialClients): void
    {
        Configuration::setPreLoadedConfig(
            Configuration::loadFromArray(array_merge(
                $this->originalModuleConfig->toArray(),
                [ModuleConfig::OPTION_DISALLOW_IMPLICIT_FOR_CONFIDENTIAL_CLIENTS => $disallowImplicitForConfidentialClients],
            )),
            ModuleConfig::DEFAULT_FILE_NAME,
        );

        $this->container = new Container();
        $this->clientRepo = $this->container->get(ClientRepository::class);
        $this->userRepo = $this->container->get(UserRepository::class);
        $this->clientFactory = $this->container->get(ClientEntityFactory::class);
        $this->authServer = $this->container->get(AuthorizationServer::class);
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;

        if (isset($this->client)) {
            $existingClient = $this->clientRepo->findById($this->clientId);
            if ($existingClient) {
                $this->clientRepo->delete($existingClient);
            }
        }
        if (isset($this->user)) {
            $existingUser = $this->userRepo->getUserEntityByIdentifier($this->userId);
            if ($existingUser) {
                $this->userRepo->delete($existingUser);
            }
        }

        Configuration::setPreLoadedConfig($this->originalModuleConfig, ModuleConfig::DEFAULT_FILE_NAME);
    }

    /**
     * Test that confidential clients MUST NOT be permitted to use the Implicit Flow
     * (response_type=id_token token or id_token).
     *
     * Requires opt-in ModuleConfig::OPTION_DISALLOW_IMPLICIT_FOR_CONFIDENTIAL_CLIENTS (enabled in setUp).
     * This is hardening, not a spec requirement. The implicit flow never authenticates the client and
     * OAuth 2.0 Security BCP advises against it: https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.2
     * OIDC Core notes confidential clients would normally use the code flow:
     * https://openid.net/specs/openid-connect-core-1_0.html#RPMTI
     */
    public function testConfidentialClientCannotUseImplicitFlow(): void
    {
        $implicitRequest = (new ServerRequest('GET', '/module.php/oidc/authorization'))
            ->withQueryParams([
                'response_type' => 'id_token token',
                'client_id' => $this->clientId,
                'redirect_uri' => $this->redirectUri,
                'scope' => 'openid',
                'state' => 'xyz123',
                'nonce' => 'nonce456',
            ]);

        // A compliant OP must reject implicit flow requests for confidential clients
        // (either during request validation or request completion by throwing an OAuth/OIDC exception)
        $this->expectException(\Throwable::class);
        $this->expectExceptionMessageMatches('/(unauthorized_client|invalid_grant|unsupported_response_type|not allowed|confidential)/i');

        $validatedAuthReq = $this->authServer->validateAuthorizationRequest($implicitRequest);
        $validatedAuthReq->setUser($this->user);
        $validatedAuthReq->setAuthorizationApproved(true);

        $response = $this->authServer->completeAuthorizationRequest(
            $validatedAuthReq,
            new Response()
        );

        // If no exception was thrown, check whether tokens were issued in the fragment (violating guidelines)
        $location = $response->getHeaderLine('Location');
        $this->assertStringNotContainsString('access_token=', $location, 'Confidential client received access_token via implicit flow!');
        $this->assertStringNotContainsString('id_token=', $location, 'Confidential client received id_token via implicit flow!');
    }

    /**
     * With the opt-in option disabled (default), behaviour is unchanged: the implicit flow works for
     * confidential clients, as the specs do not forbid it.
     */
    public function testConfidentialClientCanUseImplicitFlowWhenOptionDisabled(): void
    {
        $this->buildContainer(disallowImplicitForConfidentialClients: false);

        $implicitRequest = (new ServerRequest('GET', '/module.php/oidc/authorization'))
            ->withQueryParams([
                'response_type' => 'id_token token',
                'client_id' => $this->clientId,
                'redirect_uri' => $this->redirectUri,
                'scope' => 'openid',
                'state' => 'xyz123',
                'nonce' => 'nonce456',
            ]);

        $validatedAuthReq = $this->authServer->validateAuthorizationRequest($implicitRequest);
        $validatedAuthReq->setUser($this->user);
        $validatedAuthReq->setAuthorizationApproved(true);

        $response = $this->authServer->completeAuthorizationRequest($validatedAuthReq, new Response());

        $location = $response->getHeaderLine('Location');
        $this->assertStringContainsString('access_token=', $location);
        $this->assertStringContainsString('id_token=', $location);
    }

    /**
     * Test that confidential clients using Authorization Code Flow with PKCE
     * MUST authenticate with client credentials at the token endpoint.
     */
    public function testConfidentialClientWithPkceRequiresSecretAtTokenEndpoint(): void
    {
        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

        // Step 1: Authorization Request (receives auth code)
        $authCodeRequest = (new ServerRequest('GET', '/module.php/oidc/authorization'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => $this->clientId,
                'redirect_uri' => $this->redirectUri,
                'scope' => 'openid',
                'state' => 'state-pkce',
                'nonce' => 'nonce-pkce',
                'code_challenge' => $codeChallenge,
                'code_challenge_method' => 'S256',
            ]);

        $validatedAuthReq = $this->authServer->validateAuthorizationRequest($authCodeRequest);
        $validatedAuthReq->setUser($this->user);
        $validatedAuthReq->setAuthorizationApproved(true);

        $authResponse = $this->authServer->completeAuthorizationRequest(
            $validatedAuthReq,
            new Response()
        );

        $location = $authResponse->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'] ?? null;
        $this->assertNotEmpty($authCode, 'Authorization code was not issued');

        // Step 2: Token request WITHOUT client secret must be rejected
        $tokenRequestNoSecret = (new ServerRequest('POST', '/module.php/oidc/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'code' => $authCode,
                'redirect_uri' => $this->redirectUri,
                'code_verifier' => $codeVerifier,
            ]);

        $this->expectException(OAuthServerException::class);
        $this->authServer->respondToAccessTokenRequest(
            $tokenRequestNoSecret,
            new Response()
        );
    }

    /**
     * Test that confidential clients using standard Authorization Code Flow (no PKCE)
     * cannot exchange without secret, but succeed when valid secret is provided.
     */
    public function testConfidentialClientWithoutPkceRequiresSecretAndSucceedsWithSecret(): void
    {
        // Step 1: Authorization Request (no PKCE)
        $authCodeRequest = (new ServerRequest('GET', '/module.php/oidc/authorization'))
            ->withQueryParams([
                'response_type' => 'code',
                'client_id' => $this->clientId,
                'redirect_uri' => $this->redirectUri,
                'scope' => 'openid',
                'state' => 'state-no-pkce',
                'nonce' => 'nonce-no-pkce',
            ]);

        $validatedAuthReq = $this->authServer->validateAuthorizationRequest($authCodeRequest);
        $validatedAuthReq->setUser($this->user);
        $validatedAuthReq->setAuthorizationApproved(true);

        $authResponse = $this->authServer->completeAuthorizationRequest(
            $validatedAuthReq,
            new Response()
        );

        $location = $authResponse->getHeaderLine('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $queryParams);
        $authCode = $queryParams['code'] ?? null;
        $this->assertNotEmpty($authCode, 'Authorization code was not issued');

        // Step 2a: Token request WITHOUT client secret must fail
        $tokenRequestNoSecret = (new ServerRequest('POST', '/module.php/oidc/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'code' => $authCode,
                'redirect_uri' => $this->redirectUri,
            ]);

        try {
            $this->authServer->respondToAccessTokenRequest(
                $tokenRequestNoSecret,
                new Response()
            );
            $this->fail('Token endpoint unexpectedly issued tokens to confidential client without client credentials');
        } catch (OAuthServerException $e) {
            $this->assertSame('access_denied', $e->getErrorType());
        }

        // Step 2b: Token request WITH valid client secret succeeds
        $tokenRequestWithSecret = (new ServerRequest('POST', '/module.php/oidc/token'))
            ->withParsedBody([
                'grant_type' => 'authorization_code',
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'code' => $authCode,
                'redirect_uri' => $this->redirectUri,
            ]);

        $tokenResponse = $this->authServer->respondToAccessTokenRequest(
            $tokenRequestWithSecret,
            new Response()
        );

        $this->assertSame(200, $tokenResponse->getStatusCode());
        $body = json_decode((string) $tokenResponse->getBody(), true);
        $this->assertArrayHasKey('access_token', $body);
        $this->assertArrayHasKey('id_token', $body);
    }
}
