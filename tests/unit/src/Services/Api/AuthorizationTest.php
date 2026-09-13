<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Api;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\Api\ApiTokenPrincipalResolver;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\Utils\Auth as SspAuth;
use Symfony\Component\HttpFoundation\Request;

/**
 * Three ways in. requireSimpleSAMLphpAdmin() wants the SimpleSAMLphp admin session, and can force the login
 * first. requireTokenForAnyOfScope() takes that session when there is one and otherwise an API token, from
 * the Authorization header or, failing that, the token request parameter. requireBearerTokenForAnyOfScope()
 * takes the header and nothing else, and says who the token belongs to; its own docblock explains why.
 *
 * The bearer token is read through the real Helpers, so the Authorization header is built into a Request
 * rather than stubbed.
 */
#[CoversClass(Authorization::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthorizationTest extends TestCase
{
    protected const string TOKEN = 'a-strong-random-token';


    protected MockObject $moduleConfigMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $apiTokenPrincipalResolverMock;

    protected MockObject $sspAuthMock;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        // Not an admin unless a test says so.
        $this->sspAuthMock = $this->createMock(SspAuth::class);
        $utils = $this->createMock(Utils::class);
        $utils->method('auth')->willReturn($this->sspAuthMock);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeMock->method('utils')->willReturn($utils);

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->apiTokenPrincipalResolverMock = $this->createMock(ApiTokenPrincipalResolver::class);
        $this->apiTokenPrincipalResolverMock->method('resolve')->willReturn('HR system');
        $this->helpers = new Helpers();
    }


    protected function sut(): Authorization
    {
        return new Authorization(
            $this->moduleConfigMock,
            $this->sspBridgeMock,
            $this->requestParamsResolverMock,
            $this->helpers,
            $this->apiTokenPrincipalResolverMock,
        );
    }


    /**
     * @param array<string,string> $headers
     * @param array<string,string> $query
     */
    protected function request(array $headers = [], array $query = []): Request
    {
        $server = [];

        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return new Request($query, [], [], [], [], $server);
    }


    protected function requestWithBearerToken(): Request
    {
        return $this->request(['Authorization' => 'Bearer ' . self::TOKEN]);
    }


    /**
     * @return \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[]
     */
    protected function requiredScopes(): array
    {
        return [ApiScopesEnum::VciCredentialStatus, ApiScopesEnum::VciAll, ApiScopesEnum::All];
    }


    /**
     * The token request parameter, as the resolver answers it for this request over GET and POST.
     */
    protected function tokenParameterAnswered(Request $request, mixed $value): void
    {
        $this->requestParamsResolverMock->expects($this->once())->method('getFromRequestBasedOnAllowedMethods')
            ->with('token', $this->identicalTo($request), [HttpMethodsEnum::GET, HttpMethodsEnum::POST])
            ->willReturn($value);
    }


    protected function expectAuthorizationRefused(string $message): void
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage($message);
    }


    #[DataProvider('adminSessionProvider')]
    public function testRequiresTheAdminSessionAndCanForceTheLoginFirst(
        bool $forceAdminAuthentication,
        bool $isAdmin,
        bool $loginForced,
        ?string $refusal,
    ): void {
        $this->sspAuthMock->expects($loginForced ? $this->once() : $this->never())->method('requireAdmin');
        $this->sspAuthMock->method('isAdmin')->willReturn($isAdmin);

        if ($refusal !== null) {
            $this->expectAuthorizationRefused($refusal);
        }

        $this->sut()->requireSimpleSAMLphpAdmin($forceAdminAuthentication);
    }


    public static function adminSessionProvider(): array
    {
        return [
            'an admin session' => [false, true, false, null],
            'no admin session' => [false, false, false, 'SimpleSAMLphp Admin access required.'],
            'forced, and an admin session' => [true, true, true, null],
            'forced, and still no admin session' => [true, false, true, 'SimpleSAMLphp Admin access required.'],
        ];
    }


    /**
     * Whatever SimpleSAMLphp threw while starting the admin login comes back as an authorization failure,
     * with the cause kept, and the session is not consulted after it.
     */
    public function testWrapsAFailureToStartTheAdminLogin(): void
    {
        $cause = new RuntimeException('No admin authentication source.');
        $this->sspAuthMock->method('requireAdmin')->willThrowException($cause);
        $this->sspAuthMock->expects($this->never())->method('isAdmin');

        try {
            $this->sut()->requireSimpleSAMLphpAdmin(true);
            $this->fail('A failed admin login was accepted.');
        } catch (AuthorizationException $exception) {
            $this->assertSame('Unable to initiate admin authentication.', $exception->getMessage());
            $this->assertSame($cause, $exception->getPrevious());
        }
    }


    /**
     * An admin session authorizes on its own, with no token anywhere in the request: neither the token
     * request parameter nor any token scopes are consulted.
     */
    public function testAcceptsAnAdminSessionWithoutLookingForAToken(): void
    {
        $this->sspAuthMock->method('isAdmin')->willReturn(true);
        $this->requestParamsResolverMock->expects($this->never())->method('getFromRequestBasedOnAllowedMethods');
        $this->moduleConfigMock->expects($this->never())->method('getApiTokenScopes');

        $this->sut()->requireTokenForAnyOfScope($this->request(), $this->requiredScopes());
    }


    /**
     * The admin login is not forced on the way: a caller without the session gets to present a token.
     */
    public function testDoesNotForceTheAdminLoginBeforeLookingForAToken(): void
    {
        $this->sspAuthMock->expects($this->never())->method('requireAdmin');
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn([ApiScopesEnum::All]);

        $this->sut()->requireTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());
    }


    public function testAuthorizesATokenFromTheAuthorizationHeaderHoldingARequiredScope(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getApiTokenScopes')
            ->with(self::TOKEN)
            ->willReturn([ApiScopesEnum::VciAll]);
        // The header settles it; the request parameter is not consulted.
        $this->requestParamsResolverMock->expects($this->never())->method('getFromRequestBasedOnAllowedMethods');

        $this->sut()->requireTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());
    }


    /**
     * Without a bearer token, the token request parameter over GET or POST, trimmed.
     */
    public function testAuthorizesATokenFromTheRequestParameterHoldingARequiredScope(): void
    {
        $request = $this->request(query: ['token' => '  ' . self::TOKEN . ' ']);
        $this->tokenParameterAnswered($request, '  ' . self::TOKEN . ' ');
        $this->moduleConfigMock->expects($this->once())->method('getApiTokenScopes')
            ->with(self::TOKEN)
            ->willReturn([ApiScopesEnum::All]);

        $this->sut()->requireTokenForAnyOfScope($request, $this->requiredScopes());
    }


    /**
     * With no bearer token -- no Authorization header, or one of another scheme -- the request parameter
     * is consulted, and here it holds nothing.
     */
    #[DataProvider('noTokenProvider')]
    public function testRefusesARequestWithoutAToken(array $headers, mixed $tokenParameter): void
    {
        $request = $this->request($headers);
        $this->tokenParameterAnswered($request, $tokenParameter);
        $this->moduleConfigMock->expects($this->never())->method('getApiTokenScopes');
        $this->expectAuthorizationRefused('Authorization token not provided.');

        $this->sut()->requireTokenForAnyOfScope($request, $this->requiredScopes());
    }


    public static function noTokenProvider(): array
    {
        return [
            'nothing at all' => [[], null],
            'a blank token parameter' => [[], '   '],
            'a header of another scheme, and no token parameter' => [['Authorization' => 'Basic dXNlcjpwYXNz'], null],
        ];
    }


    #[DataProvider('noScopesProvider')]
    public function testRefusesATokenWithNoConfiguredScopes(?array $tokenScopes): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->with(self::TOKEN)->willReturn($tokenScopes);
        $this->expectAuthorizationRefused('Authorization token does not have defined scopes.');

        $this->sut()->requireTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());
    }


    public static function noScopesProvider(): array
    {
        return [
            'a token which is not configured' => [null],
            'a token configured without scopes' => [[]],
        ];
    }


    public function testRefusesATokenWhoseScopesDoNotCoverTheRequiredOnes(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->with(self::TOKEN)
            ->willReturn([ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All]);
        $this->expectAuthorizationRefused('Authorization token is not authorized for this action.');

        $this->sut()->requireTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAuthorizesABearerTokenHoldingARequiredScope(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getApiTokenScopes')
            ->with(self::TOKEN)
            ->willReturn([ApiScopesEnum::VciAll]);

        $this->assertSame(
            'HR system',
            $this->sut()->requireBearerTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes()),
        );
    }


    /**
     * It returns who the caller is, never the secret they proved it with, so that nothing downstream
     * can put a bearer token into a log line or an audit row.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testReturnsAPrincipalRatherThanTheToken(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn([ApiScopesEnum::All]);

        // Resolved from the token which actually authorized, and returned as resolved. Stubbing a
        // constant and checking it does not contain the token would pass just as well against an
        // implementation which attributed every caller to the same principal.
        $resolver = $this->createMock(ApiTokenPrincipalResolver::class);
        $resolver->expects($this->once())
            ->method('resolve')
            ->with(self::TOKEN)
            ->willReturn('the-resolved-principal');
        $this->apiTokenPrincipalResolverMock = $resolver;

        $this->assertSame(
            'the-resolved-principal',
            $this->sut()->requireBearerTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes()),
        );
    }


    /**
     * A request with no token at all is a different answer from one whose token was refused, since
     * the challenge sent back differs.
     */
    #[DataProvider('noBearerTokenProvider')]
    public function testDistinguishesAMissingTokenFromARefusedOne(array $headers): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getApiTokenScopes');
        $this->expectException(MissingTokenException::class);
        $this->expectExceptionMessage('Authorization token not provided in the Authorization header.');

        $this->sut()->requireBearerTokenForAnyOfScope($this->request($headers), $this->requiredScopes());
    }


    public static function noBearerTokenProvider(): array
    {
        return [
            'no Authorization header' => [[]],
            'a header of another scheme' => [['Authorization' => 'Basic dXNlcjpwYXNz']],
            'a Bearer header with nothing after the scheme' => [['Authorization' => 'Bearer   ']],
        ];
    }


    /**
     * The reason this method exists at all. requireTokenForAnyOfScope() authorizes an administrator's
     * session before it examines any token, which means a request carrying an administrator's cookies
     * is authorized whatever caused the browser to send it. For an endpoint which withdraws
     * credentials that is a cross-site request away from being someone else's decision. So the
     * session is not consulted at all.
     */
    public function testDoesNotAcceptAnAdministratorSessionInPlaceOfAToken(): void
    {
        $this->sspAuthMock->expects($this->never())->method('isAdmin');
        $this->sspAuthMock->expects($this->never())->method('requireAdmin');

        $this->expectException(MissingTokenException::class);
        $this->expectExceptionMessage('Authorization token not provided in the Authorization header.');

        $this->sut()->requireBearerTokenForAnyOfScope($this->request(), $this->requiredScopes());
    }


    /**
     * A token in the query string ends up in access logs, in browser history and in the Referer of
     * whatever the response links to. So the request parameter is not consulted at all.
     */
    public function testDoesNotAcceptTheTokenAsARequestParameter(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn([ApiScopesEnum::All]);
        $this->requestParamsResolverMock->expects($this->never())->method('getFromRequestBasedOnAllowedMethods');

        $this->expectException(MissingTokenException::class);
        $this->expectExceptionMessage('Authorization token not provided in the Authorization header.');

        $this->sut()->requireBearerTokenForAnyOfScope(
            $this->request([], ['token' => self::TOKEN]),
            $this->requiredScopes(),
        );
    }


    /**
     * A token which is not configured and one configured without scopes are answered the same way, the
     * same exception with the same message and not the scope one, so that a caller can not use the
     * difference to test whether a token exists.
     */
    #[DataProvider('noScopesProvider')]
    public function testRefusesABearerTokenWithNoConfiguredScopesWithoutSayingWhich(?array $tokenScopes): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->with(self::TOKEN)->willReturn($tokenScopes);
        $this->apiTokenPrincipalResolverMock->expects($this->never())->method('resolve');

        try {
            $this->sut()->requireBearerTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());

            $this->fail('An unusable token was accepted.');
        } catch (AuthorizationException $exception) {
            $this->assertSame(AuthorizationException::class, $exception::class);
            $this->assertSame('Authorization token does not have defined scopes.', $exception->getMessage());
        }
    }


    /**
     * A known token which does not cover this action is a different answer from an unusable one: the
     * caller is authenticated, and rotating its token would not help.
     */
    public function testRefusesABearerTokenWhoseScopesDoNotCoverTheAction(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->with(self::TOKEN)
            ->willReturn([ApiScopesEnum::OAuth2TokenIntrospection, ApiScopesEnum::OAuth2All]);
        $this->apiTokenPrincipalResolverMock->expects($this->never())->method('resolve');

        $this->expectException(InsufficientScopeException::class);
        $this->expectExceptionMessage('Authorization token is not authorized for this action.');

        $this->sut()->requireBearerTokenForAnyOfScope($this->requestWithBearerToken(), $this->requiredScopes());
    }
}
