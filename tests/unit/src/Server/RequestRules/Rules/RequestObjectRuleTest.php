<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
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
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core\RequestObject;
use SimpleSAML\OpenID\Jar\RequestObject as JarRequestObject;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;

#[CoversClass(RequestObjectRule::class)]
class RequestObjectRuleTest extends TestCase
{
    protected MockObject $clientStub;
    protected Stub $resultBagStub;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $requestObjectMock;
    protected MockObject $jarRequestObjectMock;
    protected MockObject $requestObjectBagMock;
    protected Stub $requestStub;
    protected Stub $loggerServiceStub;
    protected MockObject $jwksResolverMock;
    protected Helpers $helpers;
    protected Stub $responseModeStub;
    protected Stub $moduleConfigStub;

    protected function setUp(): void
    {
        $this->clientStub = $this->createMock(ClientEntityInterface::class);
        $this->clientStub->method('getIdentifier')->willReturn('client123');
        $this->resultBagStub = $this->createStub(ResultBag::class);
        $this->resultBagStub->method('getOrFail')->willReturnMap([
            [ClientRule::class, new Result(ClientRule::class, $this->clientStub)],
            [ClientRedirectUriRule::class, new Result(ClientRedirectUriRule::class, 'https://example.com/redirect')],
        ]);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestObjectMock = $this->createMock(RequestObject::class);
        $this->requestObjectMock->method('getPayload')->willReturn(['payload']);
        $this->jarRequestObjectMock = $this->createMock(JarRequestObject::class);
        $this->jarRequestObjectMock->method('getPayload')->willReturn(['payload']);
        $this->requestObjectBagMock = $this->createMock(RequestObjectBag::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?JwksResolver $jwksResolver = null,
        ?ModuleConfig $moduleConfig = null,
    ): RequestObjectRule {
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $helpers ??= $this->helpers;
        $jwksResolver ??= $this->jwksResolverMock;
        $moduleConfig ??= $this->moduleConfigStub;

        return new RequestObjectRule(
            $requestParamsResolver,
            $helpers,
            $jwksResolver,
            $moduleConfig,
        );
    }

    protected function prepareOidcRequest(): void
    {
        // A `request` param signals a Request Object is present (by value).
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        // OpenID Connect request is designated by the openid scope.
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn('openid');
        $this->requestObjectBagMock->method('get')
            ->willReturnMap([
                [RequestObject::class, $this->requestObjectMock],
            ]);
        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturn($this->requestObjectBagMock);
    }

    protected function prepareOAuth2Request(?JarRequestObject $jarRequestObject = null): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        // No openid scope, so this is a plain OAuth 2.0 request (JAR rules apply).
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn('profile');
        $this->requestObjectBagMock->method('get')
            ->willReturnMap([
                [RequestObject::class, $this->requestObjectMock],
                [JarRequestObject::class, $jarRequestObject],
            ]);
        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturn($this->requestObjectBagMock);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestObjectRule::class, $this->sut());
    }

    public function testRequestParamCanBeAbsent(): void
    {
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
        $this->assertNull($result);
    }

    public function testThrowsWhenRequestObjectSourceIsPresentButBagCannotBeResolved(): void
    {
        // `request` param present (source present), but the resolver could not parse/fetch it (null bag).
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')->willReturn('token');
        $this->requestParamsResolverMock->method('getRequestObjectBag')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testUnprotectedRequestParamCanBeUsedForOidcRequest(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }

    public function testMissingClientJwksThrows(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->jwksResolverMock->expects($this->once())->method('forClient')
            ->with($this->clientStub)->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForInvalidRequestObject(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks'])
        ->willThrowException(OidcServerException::accessDenied());
        $this->jwksResolverMock->expects($this->once())->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testReturnsValidRequestObject(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(true);
        $this->requestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks']);

        $this->jwksResolverMock->expects($this->once())
            ->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }

    public function testThrowsWhenGlobalRequireSignedRequestObjectIsEnabled(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $this->moduleConfigStub->method('getRequireSignedRequestObject')->willReturn(true);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsWhenClientRequireSignedRequestObjectIsEnabled(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);

        $this->moduleConfigStub->method('getRequireSignedRequestObject')->willReturn(false);
        $this->clientStub->method('getRequireSignedRequestObject')->willReturn(true);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testAcceptsOidcRequestWhenAudienceIncludesIssuer(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getAudience')->willReturn(['https://op.example.org/']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
    }

    public function testThrowsForOidcRequestWhenAudienceDoesNotIncludeIssuer(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getAudience')->willReturn(['https://other-op.example.org/']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForOAuth2RequestWhenAudienceDoesNotIncludeIssuer(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->method('verifyWithKeySet')->with(['jwks']);
        $this->jarRequestObjectMock->method('getAudience')->willReturn(['https://other-op.example.org/']);
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->method('forClient')->with($this->clientStub)->willReturn(['jwks']);
        $this->moduleConfigStub->method('getIssuer')->willReturn('https://op.example.org/');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testAcceptsOidcRequestWhenIssuerMatchesClient(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getIssuer')->willReturn('client123');

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
    }

    public function testThrowsForOidcRequestWhenIssuerDoesNotMatchClient(): void
    {
        $this->prepareOidcRequest();
        $this->requestObjectMock->method('isProtected')->willReturn(false);
        $this->requestObjectMock->method('getIssuer')->willReturn('otherClient');

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForOAuth2RequestWhenIssuerDoesNotMatchClient(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->method('verifyWithKeySet')->with(['jwks']);
        $this->jarRequestObjectMock->method('getIssuer')->willReturn('otherClient');
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->method('forClient')->with($this->clientStub)->willReturn(['jwks']);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForOAuth2RequestWithNonJarRequestObject(): void
    {
        // For example, an unsigned Request Object is not a valid JAR Request Object.
        $this->prepareOAuth2Request(null);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForOAuth2RequestWithMismatchedClientIdClaim(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('otherClient');
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testReturnsValidJarRequestObjectForOAuth2Request(): void
    {
        $this->jarRequestObjectMock->method('getClientId')->willReturn('client123');
        $this->jarRequestObjectMock->expects($this->once())->method('verifyWithKeySet')->with(['jwks']);
        $this->prepareOAuth2Request($this->jarRequestObjectMock);

        $this->jwksResolverMock->expects($this->once())
            ->method('forClient')
            ->with($this->clientStub)
            ->willReturn(['jwks']);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagStub,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertNotEmpty($result->getValue());
    }
}
