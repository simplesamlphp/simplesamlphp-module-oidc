<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\ProxiedIntrospectionHarness;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use GuzzleHttp\RequestOptions;
use RuntimeException;

/**
 * The proxied introspection harness (docker/proxied-introspection-harness) as its tests see it: the nodes of
 * topology.php, reached over the harness TLS, and what a test needs from them - a user's access token got the way a
 * relying party gets one, an introspection answer, a token which names an issuer without having been issued by it,
 * and what the recording upstream mock was asked.
 *
 * Only meaningful inside the harness runner, which docker/proxied-introspection-harness/run.sh starts. Not named
 * *Test, so that PHPUnit does not try to run it.
 */
final class Harness
{
    public const string AUTHORIZATION_PATH = '/simplesaml/module.php/oidc/authorization';

    public const string TOKEN_PATH = '/simplesaml/module.php/oidc/token';

    public const string INTROSPECTION_PATH = '/simplesaml/module.php/oidc/api/oauth2/token-introspection';

    /**
     * Redirects a login may take: authorization endpoint to login page, and back through SimpleSAMLphp.
     */
    private const int MAX_REDIRECTS = 10;


    private static ?self $instance = null;


    /**
     * @param array<string, mixed> $topology
     */
    private function __construct(
        private readonly array $topology,
        private readonly Client $httpClient,
    ) {
    }


    public static function get(): self
    {
        if (self::$instance instanceof self) {
            return self::$instance;
        }

        $caFile = getenv('HARNESS_CA');
        if (!is_string($caFile) || !is_file($caFile)) {
            throw new RuntimeException(
                'HARNESS_CA names no CA certificate. These tests run inside the harness: see ' .
                'docker/proxied-introspection-harness/run.sh.',
            );
        }

        /** @var array<string, mixed> $topology */
        $topology = require dirname(__DIR__, 3) . '/docker/proxied-introspection-harness/topology.php';

        return self::$instance = new self(
            $topology,
            new Client([
                RequestOptions::VERIFY => $caFile,
                RequestOptions::HTTP_ERRORS => false,
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::CONNECT_TIMEOUT => 5,
                RequestOptions::TIMEOUT => 20,
            ]),
        );
    }


    public function issuer(string $node): string
    {
        return (string)$this->node($node)['issuer'];
    }


    /**
     * A user's access token, issued by the node to the client through the authorization code flow, with the user
     * of the topology logging in at the node's login page.
     */
    public function userAccessToken(string $node, string $clientId): string
    {
        $redirectUri = (string)$this->topology['redirect_uri'];
        /** @var array{username: string, password: string} $user */
        $user = $this->topology['user'];
        $codeVerifier = $this->base64UrlEncode(random_bytes(32));
        $state = bin2hex(random_bytes(8));
        $cookies = new CookieJar();

        $url = $this->url($node, self::AUTHORIZATION_PATH) . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => 'openid profile email',
            'state' => $state,
            'nonce' => bin2hex(random_bytes(8)),
            'code_challenge' => $this->base64UrlEncode(hash('sha256', $codeVerifier, true)),
            'code_challenge_method' => 'S256',
        ]);
        $method = 'GET';
        $formParams = [];
        $code = null;

        for ($step = 0; $step <= self::MAX_REDIRECTS && is_null($code); $step++) {
            $options = [RequestOptions::COOKIES => $cookies];
            if ($method === 'POST') {
                $options[RequestOptions::FORM_PARAMS] = $formParams;
            }

            $response = $this->httpClient->request($method, $url, $options);
            $status = $response->getStatusCode();

            if ($status >= 300 && $status < 400) {
                $location = (string)UriResolver::resolve(new Uri($url), new Uri($response->getHeaderLine('Location')));

                if (str_starts_with($location, $redirectUri . '?')) {
                    parse_str((string)parse_url($location, PHP_URL_QUERY), $callback);
                    if (($callback['state'] ?? null) !== $state || !is_string($callback['code'] ?? null)) {
                        throw new RuntimeException('The node redirected back without a code: ' . $location);
                    }
                    $code = $callback['code'];
                    continue;
                }

                [$method, $url, $formParams] = ['GET', $location, []];
                continue;
            }

            $page = (string)$response->getBody();

            // The login page of the node's example authentication source.
            if ($status === 200 && preg_match('/name="AuthState" value="([^"]+)"/', $page, $authState) === 1) {
                $method = 'POST';
                $formParams = [
                    'username' => $user['username'],
                    'password' => $user['password'],
                    'AuthState' => html_entity_decode($authState[1], ENT_QUOTES | ENT_HTML5),
                ];
                continue;
            }

            throw new RuntimeException(sprintf('Unexpected HTTP %d from %s during login: %s', $status, $url, $page));
        }

        if (!is_string($code)) {
            throw new RuntimeException('No authorization code after ' . self::MAX_REDIRECTS . ' redirects.');
        }

        $response = $this->httpClient->request('POST', $this->url($node, self::TOKEN_PATH), [
            RequestOptions::AUTH => [$clientId, $this->clientSecret($node, $clientId)],
            RequestOptions::FORM_PARAMS => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'code_verifier' => $codeVerifier,
            ],
        ]);
        $body = json_decode((string)$response->getBody(), true);

        if (!is_array($body) || !is_string($body['access_token'] ?? null)) {
            throw new RuntimeException('No access token from the token endpoint: ' . $response->getBody());
        }

        return $body['access_token'];
    }


    /**
     * The node's introspection answer to the client, which authenticates with its secret (client_secret_basic).
     */
    public function introspect(
        string $node,
        string $clientId,
        string $token,
        ?string $tokenTypeHint = null,
    ): IntrospectionAnswer {
        $formParams = ['token' => $token];
        if (!is_null($tokenTypeHint)) {
            $formParams['token_type_hint'] = $tokenTypeHint;
        }

        $response = $this->httpClient->request('POST', $this->url($node, self::INTROSPECTION_PATH), [
            RequestOptions::AUTH => [$clientId, $this->clientSecret($node, $clientId)],
            RequestOptions::FORM_PARAMS => $formParams,
            RequestOptions::HEADERS => ['Accept' => 'application/json'],
        ]);

        return new IntrospectionAnswer(
            $response->getStatusCode(),
            $response->getHeaderLine('Content-Type'),
            (string)$response->getBody(),
        );
    }


    /**
     * A JWT with the given header and payload, and a signature which is not one. Nothing on the proxied path
     * verifies it (AARC-G052 section 4), and the issuer it names is the only one who could.
     *
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     */
    public function unsignedToken(array $header, array $payload): string
    {
        return implode('.', [
            $this->base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)),
            $this->base64UrlEncode(json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)),
            $this->base64UrlEncode('not a signature'),
        ]);
    }


    /**
     * How many questions the recording upstream mock was asked, and what the last one was.
     *
     * @return array{count: int, last: ?array<string, ?string>}
     */
    public function recorderState(): array
    {
        $response = $this->httpClient->request(
            'GET',
            'https://' . (string)$this->topology['upstream_mock_host'] . '/upstream-mock.php/recorder/state',
        );
        /** @var array{count: int, last: ?array<string, ?string>} $state */
        $state = json_decode((string)$response->getBody(), true, 16, JSON_THROW_ON_ERROR);

        return $state;
    }


    /**
     * The payload of a JWT, read and not verified.
     *
     * @return array<string, mixed>
     */
    public function payloadOf(string $token): array
    {
        $parts = explode('.', $token);
        /** @var array<string, mixed> $payload */
        $payload = json_decode(
            (string)base64_decode(strtr($parts[1] ?? '', '-_', '+/'), true),
            true,
            64,
            JSON_THROW_ON_ERROR,
        );

        return $payload;
    }


    private function clientSecret(string $node, string $clientId): string
    {
        /** @var array<string, array{secret: string}> $clients */
        $clients = $this->node($node)['clients'];

        return $clients[$clientId]['secret'] ?? throw new RuntimeException(
            sprintf('Node %s has no client %s in the topology.', $node, $clientId),
        );
    }


    private function url(string $node, string $path): string
    {
        return 'https://' . (string)$this->node($node)['host'] . $path;
    }


    /**
     * @return array<string, mixed>
     */
    private function node(string $node): array
    {
        /** @var array<string, array<string, mixed>> $nodes */
        $nodes = $this->topology['nodes'];

        return $nodes[$node] ?? throw new RuntimeException('The topology has no node ' . $node);
    }


    private function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
