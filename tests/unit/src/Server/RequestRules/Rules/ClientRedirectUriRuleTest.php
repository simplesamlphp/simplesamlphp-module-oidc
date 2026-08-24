<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
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
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequest')->willReturn(false);
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
            $this->check($this->resultBagFor($this->client([self::REGISTERED_URI])))?->getValue(),
        );
    }


    public function testRefusesAnUnregisteredWalletWhoseRedirectUriMatchesNoAllowedPrefix(): void
    {
        // The prefix list is the whole of the permission: a URI outside it is refused even though every
        // Verifiable Credential switch is on.
        $this->enableUnregisteredWallets(['openid-credential-offer://'], self::OTHER_URI);

        $this->expectException(OidcServerException::class);

        $this->check($this->resultBagFor($this->client([self::REGISTERED_URI])));
    }


    public function testDoesNotOfferThePrefixEscapeWhenTheRequestIsNotACredentialRequest(): void
    {
        // Both switches on, but an ordinary authorization request must still be held to the registered URI.
        $requestParamsResolver = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolver->method('getAsStringBasedOnAllowedMethods')->willReturn('openid-credential-offer://x');
        $requestParamsResolver->method('isVciAuthorizationCodeRequest')->willReturn(false);

        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $moduleConfig->method('getVciAllowNonRegisteredClients')->willReturn(true);
        $moduleConfig->method('getVciAllowedRedirectUriPrefixesForNonRegisteredClients')
            ->willReturn(['openid-credential-offer://']);

        $rule = new ClientRedirectUriRule($requestParamsResolver, new Helpers(), $moduleConfig);

        $this->expectException(OidcServerException::class);

        $rule->checkRule(
            $this->requestMock,
            $this->resultBagFor($this->client([self::REGISTERED_URI])),
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
    }


    public function testDoesNotOfferThePrefixEscapeWhenUnregisteredClientsAreNotAllowed(): void
    {
        $requestParamsResolver = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolver->method('getAsStringBasedOnAllowedMethods')->willReturn('openid-credential-offer://x');
        $requestParamsResolver->method('isVciAuthorizationCodeRequest')->willReturn(true);

        $moduleConfig = $this->createMock(ModuleConfig::class);
        $moduleConfig->method('getVciEnabled')->willReturn(true);
        $moduleConfig->method('getVciAllowNonRegisteredClients')->willReturn(false);

        $rule = new ClientRedirectUriRule($requestParamsResolver, new Helpers(), $moduleConfig);

        $this->expectException(OidcServerException::class);

        $rule->checkRule(
            $this->requestMock,
            $this->resultBagFor($this->client([self::REGISTERED_URI])),
            $this->loggerServiceMock,
            [],
            $this->responseModeMock,
        );
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
        $this->requestParamsResolverMock->method('isVciAuthorizationCodeRequest')->willReturn(true);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getVciAllowNonRegisteredClients')->willReturn(true);
        $this->moduleConfigMock->method('getVciAllowedRedirectUriPrefixesForNonRegisteredClients')
            ->willReturn($allowedPrefixes);
    }


    private function client(array|string $registeredRedirectUri): ClientEntityInterface&MockObject
    {
        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getRedirectUri')->willReturn($registeredRedirectUri);
        $client->method('getIdentifier')->willReturn('client-id');

        return $client;
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
