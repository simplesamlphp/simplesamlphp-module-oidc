<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Introspection;

use Closure;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Exceptions\UpstreamIntrospectionException;
use SimpleSAML\Module\oidc\Factories\IntrospectionReleasePolicyFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\Introspection\IntrospectionReleasePolicyInterface;
use SimpleSAML\Module\oidc\Services\Introspection\PassthroughIntrospectionReleasePolicy;
use SimpleSAML\Module\oidc\Services\Introspection\ProxiedTokenIntrospector;
use SimpleSAML\Module\oidc\Services\Introspection\UpstreamIntrospectionClient;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\ValueAbstracts\ForeignIssuerList;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectedTokenOrigin;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionAuthorization;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionReleaseDecision;
use SimpleSAML\Module\oidc\ValueAbstracts\IntrospectionUpstream;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\Jws;
use Stringable;

#[CoversClass(ProxiedTokenIntrospector::class)]
#[AllowMockObjectsWithoutExpectations]
class ProxiedTokenIntrospectorTest extends TestCase
{
    protected const string OWN_ISSUER = 'https://op.example.org';

    protected const string TOKEN_ISSUER = 'https://node-a.example.org';


    protected MockObject $moduleConfigMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $clientRepositoryMock;

    protected MockObject $upstreamIntrospectionClientMock;

    protected MockObject $introspectionReleasePolicyFactoryMock;

    protected MockObject $callerClientMock;

    protected IntrospectionUpstream $upstream;


    protected function setUp(): void
    {
        $this->upstream = new IntrospectionUpstream(
            'https://hub.example.org/',
            'https://hub.example.org/introspect',
            'our-client-id',
            'our-client-secret',
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
            2.0,
            5.0,
        );

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::OWN_ISSUER);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFor')->willReturn($this->upstream);

        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        // The resource server asking, with no foreign issuer list unless a test gives it one.
        $this->callerClientMock = $this->createMock(ClientEntity::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('findById')->with('rs1')->willReturn($this->callerClientMock);

        $this->upstreamIntrospectionClientMock = $this->createMock(UpstreamIntrospectionClient::class);

        $this->introspectionReleasePolicyFactoryMock = $this->createMock(IntrospectionReleasePolicyFactory::class);
        $this->introspectionReleasePolicyFactoryMock->method('build')
            ->willReturn(new PassthroughIntrospectionReleasePolicy());
    }


    protected function sut(): ProxiedTokenIntrospector
    {
        return new ProxiedTokenIntrospector(
            $this->moduleConfigMock,
            $this->loggerServiceMock,
            $this->clientRepositoryMock,
            $this->upstreamIntrospectionClientMock,
            $this->introspectionReleasePolicyFactoryMock,
        );
    }


    protected static function segment(array $data): string
    {
        return rtrim(strtr(base64_encode(json_encode((object)$data, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
    }


    protected static function token(array $header = ['alg' => 'RS256'], array $payload = []): string
    {
        return self::segment($header) . '.' .
        self::segment($payload + ['iss' => self::TOKEN_ISSUER, 'jti' => 'foreign1']) . '.c2lnbmF0dXJl';
    }


    /**
     * @return array<array-key, mixed>|null
     */
    protected function introspect(
        ?string $token = null,
        ?IntrospectionAuthorization $caller = null,
        ?string $tokenTypeHint = null,
    ): ?array {
        $token ??= self::token();

        return $this->sut()->introspect(
            $token,
            // Parsed as the controller parses it: with the library's parser, and not verified.
            (new Jws())->parsedJwsFactory()->fromToken($token),
            $tokenTypeHint,
            $caller ?? IntrospectionAuthorization::forResourceServer('rs1'),
        );
    }


    protected function givenTheUpstreamAnswers(array $answer): void
    {
        $this->upstreamIntrospectionClientMock->method('introspect')->willReturn($answer);
    }


    protected function givenForeignIssuerList(ForeignIssuerList $foreignIssuerList): void
    {
        $this->callerClientMock->method('getIntrospectionForeignIssuerList')->willReturn($foreignIssuerList);
    }


    /**
     * A release policy which records what it was asked, and answers as the given closure does.
     */
    protected function givenReleasePolicy(Closure $decide): IntrospectionReleasePolicyInterface
    {
        $policy = new class ($decide) implements IntrospectionReleasePolicyInterface {
            /** @var array<int, array<int, mixed>> */
            public array $asked = [];


            public function __construct(protected readonly Closure $decide)
            {
            }


            public function decide(
                IntrospectionAuthorization $caller,
                IntrospectedTokenOrigin $origin,
                array $grantedScopes,
                array $tokenMembers,
            ): IntrospectionReleaseDecision {
                $this->asked[] = [$caller, $origin, $grantedScopes, $tokenMembers];

                return ($this->decide)();
            }
        };

        $this->introspectionReleasePolicyFactoryMock = $this->createMock(IntrospectionReleasePolicyFactory::class);
        $this->introspectionReleasePolicyFactoryMock->method('build')->willReturn($policy);

        return $policy;
    }


    public function testPassesAnActiveAnswerForAResourceServerOnAsItCame(): void
    {
        $answer = [
            'active' => true,
            'scope' => 'openid profile',
            'iss' => self::TOKEN_ISSUER,
            'sub' => 'someone',
            'aud' => 'a-client-of-node-a',
            'eduperson_entitlement' => ['urn:example:entitlement'],
        ];

        $this->upstreamIntrospectionClientMock->expects($this->once())
            ->method('introspect')
            ->with($this->upstream, self::token(), 'access_token')
            ->willReturn($answer);

        $this->assertSame($answer, $this->introspect(tokenTypeHint: 'access_token'));
    }


    /**
     * The upstream is looked up by the issuer the token names.
     */
    public function testAsksTheUpstreamConfiguredForTheTokensIssuer(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::OWN_ISSUER);
        $this->moduleConfigMock->expects($this->once())
            ->method('getApiOAuth2TokenIntrospectionUpstreamFor')
            ->with(self::TOKEN_ISSUER)
            ->willReturn($this->upstream);
        $this->givenTheUpstreamAnswers(['active' => true]);

        $this->assertSame(['active' => true], $this->introspect());
    }


    public static function callersWhichAreNotResourceServersProvider(): array
    {
        return [
            'a client' => [IntrospectionAuthorization::forClient('client1')],
            'the upstream hub' => [IntrospectionAuthorization::forUpstreamHub('hub')],
            'an administrator' => [IntrospectionAuthorization::forAdministrative('simplesamlphp-admin')],
        ];
    }


    /**
     * Only a resource server's question travels upstream; the hub's would be its own question coming back.
     */
    #[DataProvider('callersWhichAreNotResourceServersProvider')]
    public function testAnswersACallerWhichIsNotAResourceServerAsInactiveWithoutAsking(
        IntrospectionAuthorization $caller,
    ): void {
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');
        $this->clientRepositoryMock->expects($this->never())->method('findById');

        $this->assertNull($this->introspect(caller: $caller));
    }


    public static function tokensRefusedBeforeForwardingProvider(): array
    {
        return [
            'longer than the limit' => [
                self::token(payload: ['padding' => str_repeat('a', ProxiedTokenIntrospector::MAX_TOKEN_LENGTH)]),
            ],
            'no algorithm' => [self::token(header: ['typ' => 'at+jwt'])],
            'an algorithm which is not a string' => [self::token(header: ['alg' => 256])],
            'an empty algorithm' => [self::token(header: ['alg' => ''])],
            'the none algorithm' => [self::token(header: ['alg' => 'none'])],
            'the none algorithm in capitals' => [self::token(header: ['alg' => 'NONE'])],
            'an http issuer' => [self::token(payload: ['iss' => 'http://node-a.example.org'])],
            'an issuer with a query' => [self::token(payload: ['iss' => 'https://node-a.example.org/?a=b'])],
            'an issuer which is not a URL' => [self::token(payload: ['iss' => 'node-a'])],
        ];
    }


    /**
     * Hygiene, not verification: a token the upstream could never answer for is not sent.
     */
    #[DataProvider('tokensRefusedBeforeForwardingProvider')]
    public function testAnswersATokenRefusedBeforeForwardingAsInactiveWithoutAsking(string $token): void
    {
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->assertNull($this->introspect(token: $token));
    }


    /**
     * Whether the issuer's algorithm is one the token can be verified with is for the authorization server which
     * verifies it to say, not for this OP, which does not verify it.
     */
    public function testForwardsATokenSignedWithAnAlgorithmThisOpDoesNotImplement(): void
    {
        $this->upstreamIntrospectionClientMock->expects($this->once())
            ->method('introspect')
            ->willReturn(['active' => true]);

        $this->assertSame(['active' => true], $this->introspect(token: self::token(header: ['alg' => 'HS256'])));
    }


    public function testForwardsATokenAtTheLengthLimit(): void
    {
        // Every three bytes of padding add four characters to the token.
        $room = ProxiedTokenIntrospector::MAX_TOKEN_LENGTH - strlen(self::token(payload: ['padding' => '']));
        $token = self::token(payload: ['padding' => str_repeat('a', 3 * intdiv($room, 4))]);
        $this->assertLessThanOrEqual(ProxiedTokenIntrospector::MAX_TOKEN_LENGTH, strlen($token));
        $this->assertGreaterThan(ProxiedTokenIntrospector::MAX_TOKEN_LENGTH - 4, strlen($token));
        $this->givenTheUpstreamAnswers(['active' => true]);

        $this->assertSame(['active' => true], $this->introspect(token: $token));
    }


    public function testAnswersATokenAsInactiveWhenNoUpstreamIsConfiguredForIt(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFor')->willReturn(null);
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->assertNull($this->introspect());
    }


    public function testAnswersAsInactiveWhenTheResourceServersOwnRecordIsGone(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('findById')->willReturn(null);
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->assertNull($this->introspect());
    }


    /**
     * A stored list which can not be applied is not read as "no list", which would lift the restriction.
     */
    public function testFailsWhenTheResourceServersIssuerListCanNotBeApplied(): void
    {
        $this->callerClientMock->method('getIntrospectionForeignIssuerList')
            ->willThrowException(new OidcException('The foreign issuer list must be either ...'));
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->expectException(OidcException::class);

        $this->introspect();
    }


    /**
     * Refusing on the issuer the token names is safe, although nobody verified it: a forger can only refuse
     * themselves. The token is never sent.
     */
    public function testRefusesAnIssuerTheResourceServerMayNotHaveBeforeAsking(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::deny([self::TOKEN_ISSUER]));
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->assertNull($this->introspect());
    }


    public function testRefusesAnIssuerOutsideTheResourceServersAllowListBeforeAsking(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::allow(['https://node-b.example.org']));
        $this->upstreamIntrospectionClientMock->expects($this->never())->method('introspect');

        $this->assertNull($this->introspect());
    }


    /**
     * An allow list never rests on the issuer the token names: the upstream's answer names the one relied on.
     */
    public function testChecksTheAllowListAgainAgainstTheIssuerTheUpstreamNames(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::allow([self::TOKEN_ISSUER]));
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => 'https://node-b.example.org']);

        $this->assertNull($this->introspect());
    }


    public function testChecksTheDenyListAgainAgainstTheIssuerTheUpstreamNames(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::deny(['https://node-b.example.org']));
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => 'https://node-b.example.org']);

        $this->assertNull($this->introspect());
    }


    public function testAnAnswerNamingNoIssuerCanNotSatisfyAList(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::deny(['https://node-b.example.org']));
        $this->givenTheUpstreamAnswers(['active' => true, 'sub' => 'someone']);

        $this->assertNull($this->introspect());
    }


    /**
     * An empty 'iss' names no issuer either: it can not satisfy a list, a deny list included.
     */
    public function testAnAnswerNamingAnEmptyIssuerCanNotSatisfyAList(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::deny(['https://node-b.example.org']));
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => '']);

        $this->assertNull($this->introspect());
    }


    public function testDoesNotTakeAnEmptyIssuerForAVerifiedOne(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => '']);
        $policy = $this->givenReleasePolicy(
            fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::releaseAll(),
        );

        $this->assertSame(['active' => true, 'iss' => ''], $this->introspect());

        $origin = $policy->asked[0][1];
        $this->assertSame(self::TOKEN_ISSUER, $origin->getIssuer());
        $this->assertFalse($origin->isIssuerVerified());
    }


    /**
     * The issuer a token names is anyone's to write, a line break included; it reaches the log escaped.
     */
    public function testLogsAnUnverifiedIssuerEscaped(): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('info')
            ->with($this->callback(
                fn(string $message): bool => !str_contains($message, "\n") &&
                    str_contains($message, 'https://node-a.example.org?FORGED LOG ENTRY'),
            ));

        $this->assertNull($this->introspect(
            token: self::token(payload: ['iss' => "https://node-a.example.org\nFORGED LOG ENTRY"]),
            caller: IntrospectionAuthorization::forClient('client1'),
        ));
    }


    public function testReleasesATokenOfAnAllowedIssuer(): void
    {
        $this->givenForeignIssuerList(ForeignIssuerList::allow([self::TOKEN_ISSUER]));
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => self::TOKEN_ISSUER]);

        $this->assertSame(['active' => true, 'iss' => self::TOKEN_ISSUER], $this->introspect());
    }


    public function testAnswersWhatTheUpstreamAnswersInactiveAsInactive(): void
    {
        $this->givenTheUpstreamAnswers(['active' => false]);

        $this->assertNull($this->introspect());
    }


    public static function tokenTypesProvider(): array
    {
        return [
            'Bearer' => ['Bearer', true],
            'bearer' => ['bearer', true],
            'N_A' => ['N_A', false],
            'refresh_token' => ['refresh_token', false],
            'DPoP' => ['DPoP', false],
        ];
    }


    /**
     * G052 section 2.4: a token which "cannot be used as an OAuth 2.0 bearer token" is answered as inactive.
     */
    #[DataProvider('tokenTypesProvider')]
    public function testReleasesOnlyATokenTheUpstreamDoesNotCallSomethingOtherThanBearer(
        string $tokenType,
        bool $isReleased,
    ): void {
        $this->givenTheUpstreamAnswers(['active' => true, 'token_type' => $tokenType]);

        $answer = $this->introspect();

        $isReleased ?
        $this->assertSame(['active' => true, 'token_type' => $tokenType], $answer) :
        $this->assertNull($answer);
    }


    public function testAnswersAsInactiveWhenTheUpstreamNamesThisOpAsTheIssuer(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => self::OWN_ISSUER]);

        $this->assertNull($this->introspect());
    }


    public function testFailsWhenNoAnswerWasHadFromUpstream(): void
    {
        $failure = UpstreamIntrospectionException::unavailable('No answer from the hub.');
        $this->upstreamIntrospectionClientMock->method('introspect')->willThrowException($failure);

        $this->loggerServiceMock->expects($this->once())->method('error')->with('No answer from the hub.');
        $this->loggerServiceMock->expects($this->never())->method('critical');

        try {
            $this->introspect();
            $this->fail('A failure to get an answer was taken for a verdict.');
        } catch (UpstreamIntrospectionException $exception) {
            $this->assertSame($failure, $exception);
        }
    }


    public function testLogsItsOwnFaultAsCritical(): void
    {
        $this->upstreamIntrospectionClientMock->method('introspect')
            ->willThrowException(UpstreamIntrospectionException::ownFault('Our credentials were refused.'));

        $this->loggerServiceMock->expects($this->once())->method('critical')->with('Our credentials were refused.');

        $this->expectException(UpstreamIntrospectionException::class);

        $this->introspect();
    }


    /**
     * The literal reading of G052 section 2.4, when the deployment asks for it.
     */
    public function testAnswersAFailureAsInactiveWhenConfiguredTo(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFailureAnswersInactive')
            ->willReturn(true);
        $this->upstreamIntrospectionClientMock->method('introspect')
            ->willThrowException(UpstreamIntrospectionException::unavailable('No answer from the hub.'));

        $this->loggerServiceMock->expects($this->once())->method('error');

        $this->assertNull($this->introspect());
    }


    /**
     * The switch covers this OP's own fault in getting the answer too (its credentials refused, say), which is still
     * logged as critical.
     */
    public function testAnswersItsOwnFaultAsInactiveWhenConfiguredTo(): void
    {
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFailureAnswersInactive')
            ->willReturn(true);
        $this->upstreamIntrospectionClientMock->method('introspect')
            ->willThrowException(UpstreamIntrospectionException::ownFault('Our credentials were refused.'));

        $this->loggerServiceMock->expects($this->once())->method('critical');

        $this->assertNull($this->introspect());
    }


    /**
     * The switch is about getting an answer from upstream, not about this OP's own configuration: an unusable
     * upstream entry is a server error whatever it says.
     */
    public function testFailsOnAMisconfiguredUpstreamEvenWhenFailuresAnswerInactive(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFailureAnswersInactive')
            ->willReturn(true);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFor')
            ->willThrowException(new ConfigurationError('Unusable next hop.'));

        $this->expectException(ConfigurationError::class);

        $this->introspect();
    }


    /**
     * The token is a credential, and never reaches the log, whichever way the question ends.
     */
    public function testNeverLogsTheToken(): void
    {
        $token = self::token();
        $logged = [];
        foreach (['debug', 'info', 'notice', 'warning', 'error', 'critical'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message) use (&$logged): void {
                    $logged[] = (string)$message;
                },
            );
        }

        $this->introspect(token: $token, caller: IntrospectionAuthorization::forClient('client1'));
        $this->givenForeignIssuerList(ForeignIssuerList::deny([self::TOKEN_ISSUER]));
        $this->introspect(token: $token);
        $this->upstreamIntrospectionClientMock->method('introspect')
            ->willThrowException(UpstreamIntrospectionException::unavailable('No answer from the hub.'));
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFailureAnswersInactive')
            ->willReturn(true);
        $this->callerClientMock = $this->createMock(ClientEntity::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->clientRepositoryMock->method('findById')->willReturn($this->callerClientMock);
        $this->introspect(token: $token);

        $this->assertGreaterThanOrEqual(3, count($logged));
        foreach ($logged as $message) {
            $this->assertStringNotContainsString($token, $message);
            $this->assertStringNotContainsString(explode('.', $token)[1], $message);
        }
    }


    public function testFailsWhenTheUpstreamIsMisconfigured(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getApiOAuth2TokenIntrospectionUpstreamFor')
            ->willThrowException(new ConfigurationError('Unusable next hop.'));

        $this->expectException(ConfigurationError::class);

        $this->introspect();
    }


    /**
     * The policy is told the token is foreign, and whose: the issuer the upstream names, verified, when it names
     * one.
     */
    public function testAsksTheReleasePolicyWithTheIssuerTheUpstreamNames(): void
    {
        $answer = ['active' => true, 'scope' => 'openid  profile', 'iss' => 'https://node-a.example.org/'];
        $this->givenTheUpstreamAnswers($answer);
        $policy = $this->givenReleasePolicy(
            fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::releaseAll(),
        );

        $this->assertSame($answer, $this->introspect());

        $this->assertCount(1, $policy->asked);
        [$caller, $origin, $grantedScopes, $tokenMembers] = $policy->asked[0];
        $this->assertSame('rs1', $caller->getCallerId());
        $this->assertFalse($origin->isLocal());
        $this->assertSame('https://node-a.example.org/', $origin->getIssuer());
        $this->assertTrue($origin->isIssuerVerified());
        $this->assertSame(['openid', 'profile'], $grantedScopes);
        $this->assertSame($answer, $tokenMembers);
    }


    public function testTellsTheReleasePolicyWhenTheIssuerIsOnlyTheTokensOwn(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true]);
        $policy = $this->givenReleasePolicy(
            fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::releaseAll(),
        );

        $this->introspect();

        $origin = $policy->asked[0][1];
        $this->assertSame(self::TOKEN_ISSUER, $origin->getIssuer());
        $this->assertFalse($origin->isIssuerVerified());
        $this->assertSame([], $policy->asked[0][2]);
    }


    public function testAnswersATokenThePolicyDeniesAsInactive(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true, 'iss' => self::TOKEN_ISSUER]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::deny());

        $this->loggerServiceMock->expects($this->once())->method('notice');

        $this->assertNull($this->introspect());
    }


    /**
     * The claims are the issuer's, and so is the mapping of scopes to claims: narrowing the scopes removes no
     * claim. The withheld members go last.
     */
    public function testAppliesTheDecisionToTheScopeAndTheWithheldMembersOnly(): void
    {
        $this->givenTheUpstreamAnswers([
            'active' => true,
            'scope' => 'openid profile email',
            'iss' => self::TOKEN_ISSUER,
            'sub' => 'someone',
            'email' => 'someone@example.org',
            'name' => 'Some One',
        ]);
        $this->givenReleasePolicy(
            fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::release(['email', 'openid'], ['name']),
        );

        $this->assertSame(
            [
                'active' => true,
                'scope' => 'openid email',
                'iss' => self::TOKEN_ISSUER,
                'sub' => 'someone',
                'email' => 'someone@example.org',
            ],
            $this->introspect(),
        );
    }


    public function testLeavesTheScopeOutWhenNoScopeIsReleased(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true, 'scope' => 'openid', 'iss' => self::TOKEN_ISSUER]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => IntrospectionReleaseDecision::release([]));

        $this->assertSame(['active' => true, 'iss' => self::TOKEN_ISSUER], $this->introspect());
    }


    public function testFailsWhenTheReleasePolicyFails(): void
    {
        $this->givenTheUpstreamAnswers(['active' => true]);
        $this->givenReleasePolicy(fn(): IntrospectionReleaseDecision => throw new RuntimeException('Policy failed.'));

        $this->expectException(RuntimeException::class);

        $this->introspect();
    }
}
