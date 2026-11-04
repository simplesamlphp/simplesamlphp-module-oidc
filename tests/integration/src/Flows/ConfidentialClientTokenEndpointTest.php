<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\integration\Flows;

use DateTimeImmutable;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Kernel;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Filesystem\Filesystem;

/**
 * A confidential client at the token endpoint, from the authorization request to the token response, through the
 * module's service definitions and an in-memory database.
 *
 * What the run needs and the repository does not provide on every branch goes in one temporary directory: the
 * signing key pair, found through SimpleSAMLphp's certdir option since the default cert directory sits in vendor/,
 * and the compiled container.
 */
#[CoversClass(AuthCodeGrant::class)]
#[CoversClass(ClientAuthenticationRule::class)]
class ConfidentialClientTokenEndpointTest extends TestCase
{
    /**
     * The answer to a confidential client which does not authenticate: one which presents nothing or a wrong secret
     * (RFC 6749 section 5.2), or an assertion which does not hold (RFC 7521 section 4.2.1).
     */
    protected const string ERROR_CLIENT_AUTHENTICATION_FAILED = 'invalid_client';

    protected const string CLIENT_ID = 'confidential-token-endpoint-client';

    protected const string CLIENT_KEY_ID = 'confidential-token-endpoint-client-key';

    protected const string CLIENT_SECRET = 'my-super-secret-key-12345';

    protected const string REDIRECT_URI = 'https://oidcdebugger.com/debug';

    protected const string USER_ID = 'token-endpoint-user';


    protected static string $workDir;

    protected array $originalServer;

    protected ClientRepository $clientRepository;

    protected UserRepository $userRepository;

    protected AuthorizationServer $authorizationServer;

    protected ClientEntityFactory $clientEntityFactory;

    protected ModuleConfig $moduleConfig;

    protected ClientEntityInterface $client;

    protected UserEntity $user;


    public static function setUpBeforeClass(): void
    {
        self::$workDir = sys_get_temp_dir() . '/oidc-token-endpoint-test-' . bin2hex(random_bytes(8));
        $certDir = self::$workDir . '/cert';
        self::createSigningKeyPair($certDir);

        Configuration::setConfigDir(dirname(__DIR__, 3) . '/config');
        $config = Configuration::getConfig('config.php')->toArray();
        $config['certdir'] = $certDir;
        $config['cachedir'] = self::$workDir . '/cache';
        $config['database.dsn'] = 'sqlite::memory:';
        $config['database.username'] = null;
        $config['database.password'] = null;
        $config['database.prefix'] = 'phpunit_';
        // Not persistent, so that this database is not the one any other test class connects to with the same DSN.
        $config['database.persistent'] = false;
        $config['database.secondaries'] = [];

        Configuration::loadFromArray($config, '', 'simplesaml');
        (new DatabaseMigration())->migrate();
    }


    public static function tearDownAfterClass(): void
    {
        Configuration::clearInternalState();

        (new Filesystem())->remove(self::$workDir);
    }


    protected function setUp(): void
    {
        $this->originalServer = $_SERVER;
        $_SERVER['HTTP_HOST'] = 'localhost';
        $_SERVER['SERVER_NAME'] = 'localhost';
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['REQUEST_URI'] = '/module.php/oidc/authorization';
        $_SERVER['REQUEST_METHOD'] = 'GET';

        $container = self::bootModuleContainer();
        $this->clientRepository = $container->get(ClientRepository::class);
        $this->userRepository = $container->get(UserRepository::class);
        $this->authorizationServer = $container->get(AuthorizationServer::class);
        $this->clientEntityFactory = $container->get(ClientEntityFactory::class);
        $this->moduleConfig = $container->get(ModuleConfig::class);

        $this->user = new UserEntity(
            self::USER_ID,
            new DateTimeImmutable(),
            new DateTimeImmutable(),
            ['sub' => self::USER_ID, 'eduPersonPrincipalName' => [self::USER_ID]],
        );
        $this->userRepository->add($this->user);

        $this->client = $this->createClient();
        $this->clientRepository->add($this->client);
    }


    protected function tearDown(): void
    {
        $_SERVER = $this->originalServer;
        Logger::setCaptureLog(false);
        Logger::clearCapturedLog();

        if (isset($this->client)) {
            $this->clientRepository->delete($this->client);
        }
        if (isset($this->user)) {
            $this->userRepository->delete($this->user);
        }
    }


    /**
     * The code_verifier proves that the caller started this authorization, not which client the caller is, so it
     * does not stand in for the secret of a confidential client.
     */
    public function testConfidentialClientWithPkceRequiresSecretAtTokenEndpoint(): void
    {
        $codeVerifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $codeChallenge = self::base64Url(hash('sha256', $codeVerifier, true));

        $code = $this->requestAuthorizationCode([
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);

        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, 'code_verifier' => $codeVerifier],
        );
        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, 'code_verifier' => $codeVerifier, 'client_secret' => 'not-the-secret'],
        );
        $this->assertTokenRequestRefused(
            'invalid_grant',
            [
                'code' => $code,
                'code_verifier' => 'not-the-verifier-but-a-well-formed-one-of-43-characters',
                'client_secret' => self::CLIENT_SECRET,
            ],
        );

        $this->assertTokensIssued(
            ['code' => $code, 'code_verifier' => $codeVerifier, 'client_secret' => self::CLIENT_SECRET],
        );
    }


    public function testConfidentialClientWithoutPkceRequiresSecretAndSucceedsWithSecret(): void
    {
        $code = $this->requestAuthorizationCode();

        $this->assertTokenRequestRefused(self::ERROR_CLIENT_AUTHENTICATION_FAILED, ['code' => $code]);
        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, 'client_secret' => 'not-the-secret'],
        );

        $this->assertTokensIssued(['code' => $code, 'client_secret' => self::CLIENT_SECRET]);
    }


    /**
     * A client which tried the Authorization header gets the challenge RFC 6749 section 5.2 requires.
     */
    public function testConfidentialClientWithoutSecretInAuthorizationHeaderIsChallenged(): void
    {
        $request = $this->tokenRequest(['code' => $this->requestAuthorizationCode()])
            ->withHeader('Authorization', 'Basic ' . base64_encode(self::CLIENT_ID . ':'));

        try {
            $this->authorizationServer->respondToAccessTokenRequest($request, new Response());
        } catch (OAuthServerException $exception) {
            $this->assertSame(self::ERROR_CLIENT_AUTHENTICATION_FAILED, $exception->getErrorType());
            $this->assertSame(401, $exception->getHttpStatusCode());
            $this->assertSame('Basic realm="OAuth"', $exception->getHttpHeaders()['WWW-Authenticate'] ?? null);
            return;
        }

        $this->fail('The token endpoint issued tokens.');
    }


    /**
     * private_key_jwt. Each refused request differs from the last one, which is accepted, only in the one thing wrong
     * with it, and a refusal does not use up the code. An assertion with a Subject other than its Issuer does not parse
     * (ClientAssertion), so the Issuer row is the one which reaches the identity checks.
     */
    public function testConfidentialClientWithClientAssertionRequiresOneWhichHolds(): void
    {
        $code = $this->requestAuthorizationCode();
        $clientKey = self::createRsaKey();

        // The client has not registered a key yet.
        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, ...$this->clientAssertionParams($clientKey)],
        );

        $this->clientRepository->update($this->createClient(self::jwksOf($clientKey)));

        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, ...$this->clientAssertionParams(self::createRsaKey())],
        );
        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            [
                'code' => $code,
                ...$this->clientAssertionParams($clientKey, ['iss' => 'another-client', 'sub' => 'another-client']),
            ],
        );
        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            ['code' => $code, ...$this->clientAssertionParams($clientKey, ['aud' => 'https://another.example.org/'])],
        );

        $this->assertTokensIssued(['code' => $code, ...$this->clientAssertionParams($clientKey)]);
    }


    /**
     * @return array<string,array{string}>
     */
    public static function lineBreakProvider(): array
    {
        return [
            'line feed' => ["\n"],
            'carriage return and line feed' => ["\r\n"],
            'next line' => ["\u{85}"],
            'line separator' => ["\u{2028}"],
            'escape, which starts a terminal sequence' => ["\x1b"],
        ];
    }


    /**
     * The library's answer to an unknown algorithm quotes the alg header, which nobody has verified at that point, so a
     * caller who knows the client_id must not be able to write lines of their own into the log that way.
     */
    #[DataProvider('lineBreakProvider')]
    public function testRefusedClientAssertionCanNotForgeLogLines(string $lineBreak): void
    {
        $code = $this->requestAuthorizationCode();
        $clientKey = self::createRsaKey();
        $this->clientRepository->update($this->createClient(self::jwksOf($clientKey)));

        Logger::setCaptureLog(true);

        $this->assertTokenRequestRefused(
            self::ERROR_CLIENT_AUTHENTICATION_FAILED,
            [
                'code' => $code,
                ...$this->clientAssertionParams(
                    $clientKey,
                    [],
                    'RS256' . $lineBreak . 'FORGED LINE' . str_repeat('x', 5000),
                ),
            ],
        );

        $logged = array_filter(
            Logger::getCapturedLog(),
            static fn(string $entry): bool => str_contains($entry, 'FORGED LINE'),
        );

        $this->assertNotEmpty($logged, 'The reason for the refusal is not in the log.');
        foreach ($logged as $entry) {
            $this->assertStringContainsString('RS256 FORGED LINE', $entry);
            $this->assertLessThan(1200, strlen($entry));
        }
    }


    protected function createClient(?array $jwks = null): ClientEntityInterface
    {
        return $this->clientEntityFactory->fromData(
            id: self::CLIENT_ID,
            secret: self::CLIENT_SECRET,
            name: 'Confidential Token Endpoint Client',
            description: 'A confidential client at the token endpoint',
            redirectUri: [self::REDIRECT_URI],
            scopes: ['openid', 'profile', 'email'],
            isEnabled: true,
            isConfidential: true,
            jwks: $jwks,
        );
    }


    /**
     * @param array<string,string> $additionalParams
     */
    protected function requestAuthorizationCode(array $additionalParams = []): string
    {
        $authorizationRequest = $this->authorizationServer->validateAuthorizationRequest(
            (new ServerRequest('GET', '/module.php/oidc/authorization'))->withQueryParams([
                'response_type' => 'code',
                'client_id' => self::CLIENT_ID,
                'redirect_uri' => self::REDIRECT_URI,
                'scope' => 'openid',
                'state' => 'state-value',
                'nonce' => 'nonce-value',
                ...$additionalParams,
            ]),
        );
        $authorizationRequest->setUser($this->user);
        $authorizationRequest->setAuthorizationApproved(true);

        $response = $this->authorizationServer->completeAuthorizationRequest($authorizationRequest, new Response());

        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);
        $this->assertNotEmpty($query['code'] ?? null, 'Authorization code was not issued');

        return (string) $query['code'];
    }


    /**
     * @param array<string,string> $params
     */
    protected function assertTokenRequestRefused(string $expectedErrorType, array $params): void
    {
        try {
            $this->authorizationServer->respondToAccessTokenRequest($this->tokenRequest($params), new Response());
        } catch (OAuthServerException $exception) {
            $this->assertSame($expectedErrorType, $exception->getErrorType());
            return;
        }

        $this->fail('The token endpoint issued tokens, expected ' . $expectedErrorType);
    }


    /**
     * @param array<string,string> $params
     */
    protected function assertTokensIssued(array $params): void
    {
        $response = $this->authorizationServer->respondToAccessTokenRequest(
            $this->tokenRequest($params),
            new Response(),
        );

        $this->assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $response->getBody(), true);
        $this->assertArrayHasKey('access_token', $body);
        $this->assertArrayHasKey('id_token', $body);
    }


    /**
     * @param array<string,string> $params
     */
    protected function tokenRequest(array $params): ServerRequest
    {
        return (new ServerRequest('POST', '/module.php/oidc/token'))->withParsedBody([
            'grant_type' => 'authorization_code',
            'client_id' => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            ...$params,
        ]);
    }


    /**
     * The parameters of a client assertion signed with the key, built by hand so that what goes over the wire is
     * what this test wrote.
     *
     * @param array<string,string> $claims Replacing those of an assertion which holds.
     * @return array<string,string>
     */
    protected function clientAssertionParams(
        OpenSSLAsymmetricKey $key,
        array $claims = [],
        string $algorithmHeader = 'RS256',
    ): array {
        $now = time();
        $signingInput = self::base64Url(json_encode(
            ['alg' => $algorithmHeader, 'typ' => 'JWT', 'kid' => self::CLIENT_KEY_ID],
            JSON_THROW_ON_ERROR,
        )) . '.' . self::base64Url(json_encode(
            [
                'iss' => self::CLIENT_ID,
                'sub' => self::CLIENT_ID,
                'aud' => $this->moduleConfig->getIssuer(),
                'jti' => bin2hex(random_bytes(16)),
                'iat' => $now,
                'exp' => $now + 300,
                ...$claims,
            ],
            JSON_THROW_ON_ERROR,
        ));

        if (!openssl_sign($signingInput, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Could not sign a client assertion.');
        }

        return [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $signingInput . '.' . self::base64Url($signature),
        ];
    }


    /**
     * The container of the module Kernel, the one the module's routes run in. Its services are private, so the ones
     * this test fetches are made public before they can be inlined or removed.
     */
    protected static function bootModuleContainer(): ContainerInterface
    {
        $kernel = new class (ModuleConfig::MODULE_NAME) extends Kernel implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                $serviceIds = [
                    AuthorizationServer::class,
                    ClientEntityFactory::class,
                    ClientRepository::class,
                    ModuleConfig::class,
                    UserRepository::class,
                ];

                foreach ($serviceIds as $serviceId) {
                    $container->getDefinition($serviceId)->setPublic(true);
                }
            }
        };
        $kernel->boot();

        return $kernel->getContainer();
    }


    protected static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }


    protected static function createRsaKey(): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false) {
            throw new RuntimeException('Could not create an RSA key.');
        }

        return $key;
    }


    /**
     * @return array{keys: list<array<string,string>>}
     */
    protected static function jwksOf(OpenSSLAsymmetricKey $key): array
    {
        $rsa = openssl_pkey_get_details($key)['rsa'];

        return ['keys' => [[
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => self::CLIENT_KEY_ID,
            'n' => self::base64Url($rsa['n']),
            'e' => self::base64Url($rsa['e']),
        ]]];
    }


    protected static function createSigningKeyPair(string $certDir): void
    {
        $key = self::createRsaKey();

        if (!mkdir($certDir, 0700, true) || !openssl_pkey_export($key, $privateKey)) {
            throw new RuntimeException('Could not create a signing key pair in ' . $certDir);
        }

        $files = [
            ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME => $privateKey,
            ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME => openssl_pkey_get_details($key)['key'],
        ];

        foreach ($files as $name => $contents) {
            if (file_put_contents($certDir . '/' . $name, $contents) === false) {
                throw new RuntimeException('Could not write ' . $name . ' to ' . $certDir);
            }
            chmod($certDir . '/' . $name, 0600);
        }
    }
}
