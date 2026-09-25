<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\ProxiedIntrospectionHarness;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * AARC-G052 proxied token introspection across three OPs of this module, over HTTP: node a issues the token, the hub
 * h knows every node, and node b asks the hub about any token it did not issue itself. Who is who is in
 * docker/proxied-introspection-harness/topology.php; docker/proxied-introspection-harness/run.sh starts the nodes and
 * runs this.
 */
#[CoversNothing]
final class ProxiedIntrospectionTest extends TestCase
{
    /**
     * The members AARC-G052 section 3 has a proxy pass on as they came, and 'aud', which this OP does not change
     * either.
     */
    private const array PROTECTED_MEMBERS = ['iss', 'exp', 'iat', 'nbf', 'token_type', 'client_id', 'jti', 'aud'];

    /**
     * An issuer no node and no issuer map knows, so that its tokens go to the next hop.
     */
    private const string UNKNOWN_ISSUER = 'https://elsewhere.oidc.test';

    /**
     * Longest an answer about an upstream which fails may take: the slow upstream answers after three seconds, and
     * node b gives it one.
     */
    private const float MAX_SECONDS_FOR_AN_UPSTREAM_FAILURE = 2.5;


    private static ?string $tokenOfA = null;

    private static ?string $tokenOfB = null;

    private Harness $harness;


    protected function setUp(): void
    {
        $this->harness = Harness::get();
    }


    public function testAResourceServerOfBLearnsAboutATokenOfAFromAThroughTheHub(): void
    {
        $token = $this->tokenOfA();

        $atA = $this->activeAnswer($this->harness->introspect('a', 'hub-h', $token));
        $atB = $this->activeAnswer($this->harness->introspect('b', 'rs-allowed', $token));

        $this->assertSame($this->harness->issuer('a'), $atB['iss'] ?? null);
        $this->assertSame($this->harness->payloadOf($token)['jti'] ?? null, $atB['jti'] ?? null);

        foreach (self::PROTECTED_MEMBERS as $member) {
            if (array_key_exists($member, $atA)) {
                $this->assertSame(
                    $atA[$member],
                    $atB[$member] ?? null,
                    sprintf('Member %s changed on the way.', $member),
                );
            }
        }

        // The user's claims, which node a released for the token's scopes.
        $this->assertSame('something@example.com', $atB['email'] ?? null);
        $this->assertSame('Firsty', $atB['given_name'] ?? null);

        // Nothing else lost or added either: the hub and node b pass the answer on as it came, under the default
        // release policy.
        $this->assertEquals($atA, $atB);
    }


    public function testBAnswersTheHubAboutATokenOfBItself(): void
    {
        $answer = $this->activeAnswer($this->harness->introspect('b', 'hub-h', $this->tokenOfB()));

        $this->assertSame($this->harness->issuer('b'), $answer['iss'] ?? null);
        $this->assertSame('something@example.com', $answer['email'] ?? null);
    }


    public function testAResourceServerOfTheHubLearnsAboutATokenOfBFromB(): void
    {
        $token = $this->tokenOfB();

        $atB = $this->activeAnswer($this->harness->introspect('b', 'hub-h', $token));
        // The hub asks node b with client_secret_post.
        $atH = $this->activeAnswer($this->harness->introspect('h', 'rs-h', $token));

        $this->assertEquals($atB, $atH);
    }


    public function testTheHubAskingBAboutATokenOfAIsAnsweredInactive(): void
    {
        $token = $this->tokenOfA();

        // Not a plain client at node b: it may introspect a token of node b which was issued to another client.
        $this->activeAnswer($this->harness->introspect('b', 'hub-h', $this->tokenOfB()));
        // Active where it was issued, so an inactive answer from node b is node b declining to send the hub's own
        // question back to the hub; a resource server's question would have been sent.
        $this->activeAnswer($this->harness->introspect('a', 'hub-h', $token));

        $this->assertInactive($this->harness->introspect('b', 'hub-h', $token));
    }


    public function testAClientOfBAskingAboutATokenOfAIsAnsweredInactive(): void
    {
        $token = $this->tokenOfA();

        $this->activeAnswer($this->harness->introspect('a', 'hub-h', $token));

        $this->assertInactive($this->harness->introspect('b', 'rp-b', $token));
    }


    /**
     * @return array<string, array{string, string, bool}>
     */
    public static function issuerListProvider(): array
    {
        return [
            'allowed node a only, a token of node a' => ['rs-allowed', 'a', true],
            'allowed node a only, a token of another issuer' => ['rs-allowed', 'another', false],
            'denied node a, a token of node a' => ['rs-denied', 'a', false],
            'denied node a, a token of another issuer' => ['rs-denied', 'another', true],
            'no list, a token of node a' => ['rs-open', 'a', true],
            'no list, a token of another issuer' => ['rs-open', 'another', true],
        ];
    }


    #[DataProvider('issuerListProvider')]
    public function testTheIssuerListOfEachResourceServerDecides(
        string $resourceServer,
        string $issuer,
        bool $isActive,
    ): void {
        // A resource server, whatever its list says: it may introspect a token of node b which was issued to another
        // client. A plain client would be refused every foreign token, list or no list.
        $this->activeAnswer($this->harness->introspect('b', $resourceServer, $this->tokenOfB()));

        // The other issuer is the upstream mock's, which answers every token active.
        $token = $issuer === 'a' ? $this->tokenOfA() : $this->tokenOfMock('active');
        $answer = $this->harness->introspect('b', $resourceServer, $token);

        $isActive ? $this->activeAnswer($answer) : $this->assertInactive($answer);
    }


    public function testATokenNodeADidNotSignIsAnsweredInactiveThroughTheHub(): void
    {
        $forged = $this->harness->unsignedToken(
            ['alg' => 'RS256', 'typ' => 'at+jwt'],
            $this->harness->payloadOf($this->tokenOfA()),
        );

        $this->assertInactive($this->harness->introspect('a', 'hub-h', $forged));
        $this->assertInactive($this->harness->introspect('b', 'rs-allowed', $forged));
    }


    public function testAnInactiveAnswerFromUpstreamIsPassedOnWithNothingElse(): void
    {
        // The mock's answer also names the subject, the issuer, the expiry and the scope.
        $this->assertInactive($this->harness->introspect('b', 'rs-open', $this->tokenOfMock('inactive')));
    }


    public function testATokenTypeOtherThanBearerUpstreamIsAnsweredInactive(): void
    {
        $this->assertInactive($this->harness->introspect('b', 'rs-open', $this->tokenOfMock('not-bearer')));
    }


    /**
     * @return array<string, array{string}>
     */
    public static function upstreamFailureProvider(): array
    {
        return [
            'HTTP 500' => ['server-error'],
            'HTTP 429' => ['too-many-requests'],
            'HTTP 401, the node\'s own credentials refused' => ['unauthorized'],
            'an answer which is not JSON' => ['not-json'],
            'no answer within the timeout' => ['slow'],
        ];
    }


    #[DataProvider('upstreamFailureProvider')]
    public function testNoAnswerFromUpstreamIsAServerError(string $case): void
    {
        $started = microtime(true);
        $answer = $this->harness->introspect('b', 'rs-open', $this->tokenOfMock($case));

        $this->assertSame(500, $answer->status, $answer->describe());
        $this->assertSame('server_error', $answer->json()['error'] ?? null, $answer->describe());
        $this->assertArrayNotHasKey('active', $answer->json() ?? [], $answer->describe());
        $this->assertLessThan(self::MAX_SECONDS_FOR_AN_UPSTREAM_FAILURE, microtime(true) - $started);
    }


    #[DataProvider('upstreamFailureProvider')]
    public function testNoAnswerFromUpstreamIsAnInactiveTokenWhereG052IsReadLiterally(string $case): void
    {
        $started = microtime(true);

        $this->assertInactive($this->harness->introspect('b-literal', 'rs-open', $this->tokenOfMock($case)));
        $this->assertLessThan(self::MAX_SECONDS_FOR_AN_UPSTREAM_FAILURE, microtime(true) - $started);
    }


    public function testAWellFormedTokenOfAnUnknownIssuerIsSentToTheNextHop(): void
    {
        $token = $this->tokenNaming(self::UNKNOWN_ISSUER);
        $countBefore = $this->harness->recorderState()['count'];

        // The recording mock, node b-literal's next hop, answers every token inactive.
        $this->assertInactive($this->harness->introspect('b-literal', 'rs-open', $token, 'access_token'));

        $state = $this->harness->recorderState();
        $this->assertSame($countBefore + 1, $state['count']);
        $this->assertSame($token, $state['last']['token'] ?? null);
        $this->assertSame('access_token', $state['last']['token_type_hint'] ?? null);
        // The node's own credentials at the upstream, never the caller's.
        $this->assertSame('node-b', $state['last']['basic_client_id'] ?? null);
        $this->assertNull($state['last']['post_client_id'] ?? null);
    }


    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function tokenRefusedBeforeForwardingProvider(): array
    {
        return [
            'alg none' => [['alg' => 'none'], self::UNKNOWN_ISSUER],
            'alg None' => [['alg' => 'None'], self::UNKNOWN_ISSUER],
            'no alg' => [[], self::UNKNOWN_ISSUER],
            'an http issuer' => [['alg' => 'RS256'], 'http://elsewhere.oidc.test'],
            'an issuer with a query' => [['alg' => 'RS256'], self::UNKNOWN_ISSUER . '?tenant=1'],
        ];
    }


    /**
     * @param array<string, mixed> $header
     */
    #[DataProvider('tokenRefusedBeforeForwardingProvider')]
    public function testATokenRefusedBeforeForwardingIsNeverSentUpstream(array $header, string $issuer): void
    {
        $token = $this->harness->unsignedToken($header + ['typ' => 'at+jwt'], $this->payloadNaming($issuer));
        $countBefore = $this->harness->recorderState()['count'];

        $this->assertInactive($this->harness->introspect('b-literal', 'rs-open', $token));

        $this->assertSame($countBefore, $this->harness->recorderState()['count']);
    }


    public function testANextHopWhichIsTheNodeItselfIsAServerError(): void
    {
        $countBefore = $this->harness->recorderState()['count'];

        $answer = $this->harness->introspect('b-loop', 'rs-open', $this->tokenNaming(self::UNKNOWN_ISSUER));

        $this->assertSame(500, $answer->status, $answer->describe());
        $this->assertSame('server_error', $answer->json()['error'] ?? null, $answer->describe());
        // Refused by the configuration check, not by the network: node b-loop may reach the endpoint its next hop
        // names, which is the recorder's.
        $this->assertSame($countBefore, $this->harness->recorderState()['count']);
    }


    private function tokenOfA(): string
    {
        return self::$tokenOfA ??= $this->harness->userAccessToken('a', 'rp-a');
    }


    private function tokenOfB(): string
    {
        return self::$tokenOfB ??= $this->harness->userAccessToken('b', 'rp-b');
    }


    /**
     * A token naming the upstream mock of the given case as its issuer, which node b's issuer map sends to it.
     */
    private function tokenOfMock(string $case): string
    {
        return $this->tokenNaming('https://upstream-mock.oidc.test/' . $case);
    }


    private function tokenNaming(string $issuer): string
    {
        return $this->harness->unsignedToken(['alg' => 'RS256', 'typ' => 'at+jwt'], $this->payloadNaming($issuer));
    }


    /**
     * @return array<string, mixed>
     */
    private function payloadNaming(string $issuer): array
    {
        return [
            'iss' => $issuer,
            'sub' => 'someone',
            'client_id' => 'a-client',
            'aud' => 'a-client',
            'jti' => bin2hex(random_bytes(8)),
            'iat' => time(),
            'exp' => time() + 600,
            'scope' => 'openid',
        ];
    }


    /**
     * @return array<string, mixed>
     */
    private function activeAnswer(IntrospectionAnswer $answer): array
    {
        $this->assertSame(200, $answer->status, $answer->describe());
        $json = $answer->json();
        $this->assertIsArray($json, $answer->describe());
        $this->assertTrue($json['active'] ?? null, $answer->describe());

        return $json;
    }


    /**
     * An inactive answer says nothing else (RFC 7662 section 2.2; AARC-G052 section 3).
     */
    private function assertInactive(IntrospectionAnswer $answer): void
    {
        $this->assertSame(200, $answer->status, $answer->describe());
        $this->assertStringStartsWith('application/json', $answer->contentType, $answer->describe());
        $this->assertSame(['active' => false], $answer->json(), $answer->describe());
    }
}
