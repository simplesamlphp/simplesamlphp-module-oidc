<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientAuthenticationRule
 */
class ClientAuthenticationRuleTest extends TestCase
{
    protected ResultBag $resultBag;
    protected Stub $clientStub;
    protected Stub $requestStub;
    protected Stub $loggerServiceStub;
    protected MockObject $requestParamsResolverMock;
    protected Helpers $helpers;
    protected MockObject $authenticatedOAuth2ClientResolverMock;
    protected Stub $responseModeStub;

    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?AuthenticatedOAuth2ClientResolver $authenticatedOAuth2ClientResolver = null,
    ): ClientAuthenticationRule {
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $helpers ??= $this->helpers;
        $authenticatedOAuth2ClientResolver ??= $this->authenticatedOAuth2ClientResolverMock;

        return new ClientAuthenticationRule(
            $requestParamsResolver,
            $helpers,
            $authenticatedOAuth2ClientResolver,
        );
    }

    /**
     * A client already resolved by an upstream rule (ClientRule) is used as the pre-fetched client, without
     * touching the client_id request parameter.
     *
     * @throws \Throwable
     */
    public function testUsesPreFetchedClientFromResultBag(): void
    {
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));

        $resolved = new ResolvedClientAuthenticationMethod(
            $this->clientStub,
            ClientAuthenticationMethodsEnum::ClientSecretBasic,
        );

        // The client_id param fallback must not be consulted when a client is already available.
        $this->requestParamsResolverMock->expects($this->never())
            ->method('getAsStringBasedOnAllowedMethods');
        $this->authenticatedOAuth2ClientResolverMock->expects($this->never())
            ->method('findActiveClient');

        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestStub), $this->identicalTo($this->clientStub))
            ->willReturn($resolved);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($resolved, $result->getValue());
    }

    /**
     * When no upstream client is available but a client_id param is present, it is used to pre-fetch the client.
     *
     * @throws \Throwable
     */
    public function testFallsBackToClientIdParameterWhenPresent(): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('client123');

        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())
            ->method('findActiveClient')
            ->with('client123')
            ->willReturn($this->clientStub);

        $resolved = new ResolvedClientAuthenticationMethod(
            $this->clientStub,
            ClientAuthenticationMethodsEnum::ClientSecretPost,
        );

        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestStub), $this->identicalTo($this->clientStub))
            ->willReturn($resolved);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($resolved, $result->getValue());
    }

    /**
     * The core of the fix: with no upstream client and no client_id parameter (e.g. private_key_jwt, where the
     * identity is conveyed by the assertion), the rule must still authenticate by letting the resolver derive the
     * client from the presented authentication material - it must NOT reject the request for a missing client_id.
     *
     * @throws \Throwable
     */
    public function testDoesNotRequireClientIdParameter(): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturn(null);

        // With no client_id param, no pre-fetch lookup must happen...
        $this->authenticatedOAuth2ClientResolverMock->expects($this->never())
            ->method('findActiveClient');

        $resolved = new ResolvedClientAuthenticationMethod(
            $this->clientStub,
            ClientAuthenticationMethodsEnum::PrivateKeyJwt,
        );

        // ...and the resolver is invoked with a null pre-fetched client.
        $this->authenticatedOAuth2ClientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->identicalTo($this->requestStub), null)
            ->willReturn($resolved);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($resolved, $result->getValue());
    }

    /**
     * If the resolver can not authenticate the client by any supported method, the request is denied.
     *
     * @throws \Throwable
     */
    public function testThrowsWhenNoAuthenticationMethodResolved(): void
    {
        $this->requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')
            ->willReturn(null);

        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn(null);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    /**
     * A confidential client must not authenticate using the 'none' method.
     *
     * @throws \Throwable
     */
    public function testThrowsWhenConfidentialClientUsesNone(): void
    {
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $this->clientStub->method('isConfidential')->willReturn(true);

        $resolved = new ResolvedClientAuthenticationMethod(
            $this->clientStub,
            ClientAuthenticationMethodsEnum::None,
        );

        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willReturn($resolved);

        $this->expectException(OidcServerException::class);

        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }
}
