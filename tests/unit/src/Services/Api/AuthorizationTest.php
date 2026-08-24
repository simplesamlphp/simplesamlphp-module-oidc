<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Services\Api;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
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
use SimpleSAML\Utils\Auth as SspAuth;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(Authorization::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthorizationTest extends TestCase
{
    protected const string TOKEN = 'a-strong-random-token';


    protected MockObject $moduleConfigMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $apiTokenPrincipalResolverMock;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
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


    /**
     * @return \SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum[]
     */
    protected function requiredScopes(): array
    {
        return [ApiScopesEnum::VciCredentialStatus, ApiScopesEnum::VciAll, ApiScopesEnum::All];
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function testAuthorizesABearerTokenHoldingARequiredScope(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn([ApiScopesEnum::VciAll]);

        $this->assertSame(
            'HR system',
            $this->sut()->requireBearerTokenForAnyOfScope(
                $this->request(['Authorization' => 'Bearer ' . self::TOKEN]),
                $this->requiredScopes(),
            ),
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
            $this->sut()->requireBearerTokenForAnyOfScope(
                $this->request(['Authorization' => 'Bearer ' . self::TOKEN]),
                $this->requiredScopes(),
            ),
        );
    }


    /**
     * A request with no token at all is a different answer from one whose token was refused, since
     * the challenge sent back differs.
     */
    public function testDistinguishesAMissingTokenFromARefusedOne(): void
    {
        $this->expectException(MissingTokenException::class);

        $this->sut()->requireBearerTokenForAnyOfScope($this->request(), $this->requiredScopes());
    }


    /**
     * The reason this method exists at all. requireTokenForAnyOfScope() authorizes an administrator's
     * session before it examines any token, which means a request carrying an administrator's cookies
     * is authorized whatever caused the browser to send it. For an endpoint which withdraws
     * credentials that is a cross-site request away from being someone else's decision.
     */
    public function testDoesNotAcceptAnAdministratorSessionInPlaceOfAToken(): void
    {
        $auth = $this->createMock(SspAuth::class);
        $auth->method('isAdmin')->willReturn(true);
        $utils = $this->createMock(Utils::class);
        $utils->method('auth')->willReturn($auth);
        $this->sspBridgeMock->method('utils')->willReturn($utils);

        $this->expectException(AuthorizationException::class);

        $this->sut()->requireBearerTokenForAnyOfScope($this->request(), $this->requiredScopes());
    }


    /**
     * A token in the query string ends up in access logs, in browser history and in the Referer of
     * whatever the response links to.
     */
    public function testDoesNotAcceptTheTokenAsARequestParameter(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn([ApiScopesEnum::All]);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturn(self::TOKEN);

        $this->expectException(AuthorizationException::class);

        $this->sut()->requireBearerTokenForAnyOfScope(
            $this->request([], ['token' => self::TOKEN]),
            $this->requiredScopes(),
        );
    }


    public function testRefusesARequestWithNoAuthorizationHeader(): void
    {
        $this->expectException(AuthorizationException::class);

        $this->sut()->requireBearerTokenForAnyOfScope($this->request(), $this->requiredScopes());
    }


    public function testRefusesATokenWithNoConfiguredScopes(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn(null);

        $this->expectException(AuthorizationException::class);

        $this->sut()->requireBearerTokenForAnyOfScope(
            $this->request(['Authorization' => 'Bearer ' . self::TOKEN]),
            $this->requiredScopes(),
        );
    }


    /**
     * A known token which does not cover this action is a different answer from an unusable one: the
     * caller is authenticated, and rotating its token would not help.
     */
    public function testRefusesATokenWhoseScopesDoNotCoverTheAction(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')
            ->willReturn([ApiScopesEnum::OAuth2TokenIntrospection]);

        $this->expectException(InsufficientScopeException::class);

        $this->sut()->requireBearerTokenForAnyOfScope(
            $this->request(['Authorization' => 'Bearer ' . self::TOKEN]),
            $this->requiredScopes(),
        );
    }


    /**
     * A token which is not configured and one configured without scopes are answered the same way, so
     * that a caller can not use the difference to test whether a token exists.
     */
    public function testDoesNotDistinguishAnUnknownTokenFromOneWithoutScopes(): void
    {
        $this->moduleConfigMock->method('getApiTokenScopes')->willReturn(null);

        try {
            $this->sut()->requireBearerTokenForAnyOfScope(
                $this->request(['Authorization' => 'Bearer ' . self::TOKEN]),
                $this->requiredScopes(),
            );

            $this->fail('An unusable token was accepted.');
        } catch (AuthorizationException $exception) {
            $this->assertNotInstanceOf(
                InsufficientScopeException::class,
                $exception,
                'An unusable token was reported as a scope problem, which reveals that it exists.',
            );
        }
    }
}
