<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * Redirect URI validation.
 *
 * This is the control that stops an authorization code being delivered somewhere the client never
 * registered, so every mismatch case has to end in a refusal. The one exception is deliberate: a wallet
 * that was never registered can be admitted by prefix, but only when Verifiable Credential issuance is
 * enabled, only when non-registered clients are allowed, and only for a credential request.
 */
#[CoversClass(ClientRedirectUriRule::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[AllowMockObjectsWithoutExpectations]
class ClientRedirectUriRuleTest extends TestCase
{
    private const string REGISTERED_URI = 'https://rp.example.org/callback';

    private const string OTHER_URI = 'https://attacker.example.org/callback';


    private RequestParamsResolver&MockObject $requestParamsResolverMock;

    private ModuleConfig&MockObject $moduleConfigMock;

    private ServerRequestInterface&MockObject $requestMock;

    private LoggerService&MockObject $loggerServiceMock;

    private ResponseModeInterface&MockObject $responseModeMock;


    protected function setUp(): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->responseModeMock = $this->createMock(ResponseModeInterface::class);

        // Off unless a test turns it on, so the ordinary path cannot accidentally take the wallet escape.
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequestWithIssuerState')->willReturn(false);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);
        $this->moduleConfigMock->method('getVciAllowNonRegisteredClients')->willReturn(false);
    }


    public function testRequiresTheClientToHaveBeenResolvedFirst(): void
    {
        $this->expectException(LogicException::class);

        $this->check(new ResultBag());
    }


    public function testRefusesToCheckAgainstSomethingThatIsNotAClient(): void
    {
        // The bag is untyped, so a rule that put the wrong thing under ClientRule would otherwise have this
        // rule comparing a redirect URI against whatever that was.
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, 'not-a-client'));

        $this->expectException(LogicException::class);

        $this->check($resultBag);
    }


    public function testRejectsARequestWithoutARedirectUri(): void
    {
        // OAuth 2.0 allows omitting it when only one is registered; OpenID Connect requires it, and this
        // module follows OpenID Connect.
        $this->resolverReturns(null);

        try {
            $this->check($this->resultBagFor($this->client(self::REGISTERED_URI)));
            $this->fail('A request without a redirect_uri must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }
    }


    public function testAcceptsTheRedirectUriRegisteredAsAString(): void
    {
        $this->resolverReturns(self::REGISTERED_URI);

        $this->assertSame(
            self::REGISTERED_URI,
            $this->check($this->resultBagFor($this->client(self::REGISTERED_URI)))?->getValue(),
        );
    }


    public function testRejectsARedirectUriThatDiffersFromTheOneRegisteredAsAString(): void
    {
        $this->resolverReturns(self::OTHER_URI);

        $this->expectException(OidcServerException::class);

        $this->check($this->resultBagFor($this->client(self::REGISTERED_URI)));
    }


    public function testAcceptsARedirectUriPresentInTheRegisteredList(): void
    {
        $this->resolverReturns(self::REGISTERED_URI);

        $client = $this->client(['https://rp.example.org/other', self::REGISTERED_URI]);

        $this->assertSame(self::REGISTERED_URI, $this->check($this->resultBagFor($client))?->getValue());
    }


    public function testRejectsARedirectUriAbsentFromTheRegisteredList(): void
    {
        $this->resolverReturns(self::OTHER_URI);

        try {
            $this->check($this->resultBagFor($this->client([self::REGISTERED_URI])));
            $this->fail('A redirect_uri outside the registered list must be rejected.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
        }
    }


    public function testMatchesTheRegisteredListExactlyRatherThanByPrefix(): void
    {
        // A registered https://rp.example.org/callback must not admit .../callback/../elsewhere or a
        // lookalike that merely starts the same way.
        $this->resolverReturns(self::REGISTERED_URI . '.evil.example.org');

        $this->expectException(OidcServerException::class);

        $this->check($this->resultBagFor($this->client([self::REGISTERED_URI])));
    }

    // The Verifiable Credential escape hatch for wallets that were never registered.

    public function testAdmitsAnUnregisteredWalletWhoseRedirectUriMatchesAnAllowedPrefix(): void
    {
        $walletUri = 'openid-credential-offer://callback';
        $this->enableUnregisteredWallets(['openid-credential-offer://'], $walletUri);

        $this->assertSame(
            $walletUri,
            $this->check($this->resultBagFor($this->genericClient()))?->getValue(),
        );
    }


    /**
     * The prefixes stand in for a registration, so a client which has one is held to it: a registered client's
     * credential request, every switch on and the redirect URI matching an allowed prefix, is still refused when
     * the URI is not one it registered.
     */
    public function testHoldsARegisteredClientToItsRegisteredRedirectUrisInACredentialRequestToo(): void
    {
        $this->enableUnregisteredWallets(['openid-credential-offer://'], 'openid-credential-offer://callback');

        $this->expectException(OidcServerException::class);

        $this->check($this->resultBagFor($this->client([self::REGISTERED_URI])));
    }


    public function testRefusesAnUnregisteredWalletWhoseRedirectUriMatchesNoAllowedPrefix(): void
    {
        // The prefix list is the whole of the permission: a URI outside it is refused even though every
        // Verifiable Credential switch is on.
        $this->enableUnregisteredWallets(['openid-credential-offer://'], self::OTHER_URI);

        $this->expectException(OidcServerException::class);

        $this->check($this->resultBagFor($this->genericClient()));
    }


    public function testDoesNotOfferThePrefixEscapeWhenTheRequestIsNotACredentialRequest(): void
    {
        // Both switches on, but an ordinary authorization request must still be held to the registered URI.
        $requestParamsResolver = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolver->method('getAsStringBasedOnAllowedMethods')->willReturn('openid-credential-offer://x');
        $requestParamsResolver->method('isVciAuthorizationCodeRequestWithIssuerState')->willReturn(false);

        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $moduleConfig->method('getVciAllowNonRegisteredClients')->willReturn(true);
        $moduleConfig->method('getVciAllowedRedirectUriPrefixesForNonRegisteredClients')
            ->willReturn(['openid-credential-offer://']);

        $rule = new ClientRedirectUriRule($requestParamsResolver, new Helpers(), $moduleConfig);

        $this->expectException(OidcServerException::class);

        $rule->checkRule(
            $this->requestMock,
            $this->resultBagFor($this->genericClient()),
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }


    public function testDoesNotOfferThePrefixEscapeWhenUnregisteredClientsAreNotAllowed(): void
    {
        $requestParamsResolver = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolver->method('getAsStringBasedOnAllowedMethods')->willReturn('openid-credential-offer://x');
        $requestParamsResolver->method('isVciAuthorizationCodeRequestWithIssuerState')->willReturn(true);

        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $moduleConfig->method('getVciAllowNonRegisteredClients')->willReturn(false);
        $moduleConfig->method('getVciAllowedRedirectUriPrefixesForNonRegisteredClients')
            ->willReturn(['openid-credential-offer://']);

        $rule = new ClientRedirectUriRule($requestParamsResolver, new Helpers(), $moduleConfig);

        $this->expectException(OidcServerException::class);

        $rule->checkRule(
            $this->requestMock,
            $this->resultBagFor($this->genericClient()),
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }


    // HAIP: no http redirect URI but the loopback one of a native client.

    /**
     * While issuance follows HAIP, an issuance request is answered at no `http` redirect URI but the loopback one of
     * a native client (FAPI 2.0 section 5.3.2.2, RFC 8252 section 7.3), whatever its port; `https` and custom schemes
     * are not affected, and the request is not asked about for them.
     */
    #[DataProvider('haipRedirectUriProvider')]
    public function testTakesNoHttpRedirectUriButANativeLoopbackOneForIssuanceFollowingHaip(
        string $redirectUri,
        ?string $applicationType,
        bool $isAccepted,
    ): void {
        $this->resolverReturns($redirectUri);
        $this->requestParamsResolverMock
            ->expects(preg_match('/^[\x00-\x20]*http:/i', $redirectUri) === 1 ? $this->once() : $this->never())
            ->method('isVciHaipIssuanceRequest')
            ->with($this->requestMock, [HttpMethodsEnum::GET])
            ->willReturn(true);
        $resultBag = $this->resultBagFor($this->client([$redirectUri], applicationType: $applicationType));

        if ($isAccepted) {
            $this->assertSame($redirectUri, $this->check($resultBag)?->getValue());

            return;
        }

        $this->assertRefusedWithoutARedirect($resultBag);
    }


    public static function haipRedirectUriProvider(): array
    {
        return [
            'the IPv4 loopback, native' => ['http://127.0.0.1:61234/callback', 'native', true],
            'the IPv6 loopback, native' => ['http://[::1]:61234/callback', 'native', true],
            'the IPv4 loopback without a port, native' => ['http://127.0.0.1/callback', 'native', true],
            'the scheme in capitals, the IPv4 loopback, native' => ['HTTP://127.0.0.1:61234/callback', 'native', true],
            'the IPv4 loopback, web' => ['http://127.0.0.1:61234/callback', 'web', false],
            'the IPv4 loopback, no application type' => ['http://127.0.0.1:61234/callback', null, false],
            'localhost, native' => ['http://localhost:61234/callback', 'native', false],
            'another loopback address, native' => ['http://127.0.0.2:61234/callback', 'native', false],
            'a host name, native' => ['http://wallet.example.org/callback', 'native', false],
            'the scheme in capitals, a host name, web' => ['HTTP://wallet.example.org/callback', 'web', false],
            'a query after the IPv6 loopback, native' => ['http://[::1]:61234?flow=issuance', 'native', true],
            // parse_url() reads 127.0.0.1 for the host, where a browser, reading the backslash as a slash, goes to
            // attacker.example.
            'a backslash before the address, native' => [
                'http://attacker.example\\@127.0.0.1/callback',
                'native',
                false,
            ],
            'userinfo, native' => ['http://wallet@127.0.0.1:61234/callback', 'native', false],
            'a backslash in the path, native' => ['http://127.0.0.1:61234/a\\b', 'native', false],
            // A browser removes the tab, and goes to 127.0.0.1.attacker.example.
            'a tab after the address, native' => ["http://127.0.0.1\t.attacker.example/callback", 'native', false],
            // A browser strips the space, and takes the URI for an http one.
            'a space before a host name, web' => [' http://wallet.example.org/callback', 'web', false],
            'https, web' => ['https://wallet.example.org/callback', 'web', true],
            'a custom scheme, native' => ['eu.example.wallet://callback', 'native', true],
        ];
    }


    /**
     * A request which is not an issuance one following HAIP keeps the `http` redirect URI its client registered.
     */
    public function testTakesAnHttpRedirectUriForARequestWhichIsNotAnIssuanceOneFollowingHaip(): void
    {
        $this->resolverReturns('http://rp.example.org/callback');
        $this->requestParamsResolverMock->expects($this->once())->method('isVciHaipIssuanceRequest')
            ->willReturn(false);

        $this->assertSame(
            'http://rp.example.org/callback',
            $this->check($this->resultBagFor($this->client(['http://rp.example.org/callback'])))?->getValue(),
        );
    }


    /**
     * A wallet admitted by a prefix is held to the same rule, having no application type of its own.
     */
    public function testHoldsAWalletAdmittedByPrefixToTheRuleForIssuanceFollowingHaip(): void
    {
        $this->enableUnregisteredWallets(['http://'], 'http://127.0.0.1:61234/callback');
        $this->requestParamsResolverMock->method('isVciHaipIssuanceRequest')->willReturn(true);

        $this->assertRefusedWithoutARedirect($this->resultBagFor($this->genericClient()));
    }


    private function assertRefusedWithoutARedirect(ResultBag $resultBag): void
    {
        $this->loggerServiceMock->expects($this->once())->method('warning')->with(
            'Request rejected: credential issuance following HAIP takes no http redirect URI but the loopback one ' .
            'of a native client.',
            $this->anything(),
        );

        try {
            $this->check($resultBag);
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertFalse($exception->hasRedirect());

            return;
        }

        $this->fail('The redirect URI was not refused.');
    }


    private function resolverReturns(?string $redirectUri): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn($redirectUri);
    }


    /**
     * Replaces the resolver and config wholesale, so the redirect URI has to be restated here: a mock
     * keeps the first matcher registered for a method, so re-stubbing the old one would have no effect.
     *
     * @param string[] $allowedPrefixes
     */
    private function enableUnregisteredWallets(array $allowedPrefixes, string $redirectUri): void
    {
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn($redirectUri);
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequestWithIssuerState')->willReturn(true);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciAllowNonRegisteredClients')->willReturn(true);
        $this->moduleConfigMock->method('getVciAllowedRedirectUriPrefixesForNonRegisteredClients')
            ->willReturn($allowedPrefixes);
    }


    private function client(
        array|string $registeredRedirectUri,
        bool $isGeneric = false,
        ?string $applicationType = null,
    ): ClientEntityInterface&MockObject {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getRedirectUri')->willReturn($registeredRedirectUri);
        $client->method('getIdentifier')->willReturn('client-id');
        $client->method('isGeneric')->willReturn($isGeneric);
        $client->method('getApplicationType')->willReturn($applicationType);

        return $client;
    }


    /**
     * The client ClientRule hands a wallet which is not registered, with the redirect URI the generic client is
     * built with.
     */
    private function genericClient(): ClientEntityInterface&MockObject
    {
        return $this->client(['openid-credential-offer://'], true);
    }


    private function resultBagFor(ClientEntityInterface $client): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $client));

        return $resultBag;
    }


    private function check(ResultBag $resultBag): ?Result
    {
        $rule = new ClientRedirectUriRule(
            $this->requestParamsResolverMock,
            new Helpers(),
            $this->moduleConfigMock,
        );

        return $rule->checkRule(
            $this->requestMock,
            $resultBag,
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }
}
