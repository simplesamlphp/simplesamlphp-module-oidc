<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;

#[CoversClass(RequestUriRule::class)]
#[UsesClass(Result::class)]
class RequestUriRuleTest extends TestCase
{
    protected const PAR_REQUEST_URI = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
    protected const HTTPS_REQUEST_URI = 'https://client.example.org/request-object.jwt';

    protected MockObject $clientMock;
    protected MockObject $resultBagMock;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $pushedAuthorizationRequestRepositoryMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $parEntityMock;
    protected Stub $requestStub;
    protected MockObject $loggerServiceMock;
    protected Helpers $helpers;
    protected Stub $responseModeStub;

    protected function setUp(): void
    {
        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn('client123');
        $this->resultBagMock = $this->createMock(ResultBag::class);
        $this->resultBagMock->method('getOrFail')->willReturnMap([
            [ClientRule::class, new Result(ClientRule::class, $this->clientMock)],
        ]);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getRequestUriParameterSupported')->willReturn(true);
        $this->parEntityMock = $this->createMock(PushedAuthorizationRequestEntity::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }

    protected function sut(): RequestUriRule
    {
        return new RequestUriRule(
            $this->requestParamsResolverMock,
            $this->helpers,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->moduleConfigMock,
        );
    }

    /**
     * Set raw request params which will be resolved from the request itself (not the merged view).
     *
     * @param array<string, ?string> $params
     */
    protected function prepareRawParams(array $params): void
    {
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(fn(string $paramKey): ?string => $params[$paramKey] ?? null);
    }

    protected function checkRule(): mixed
    {
        return $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBagMock,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestUriRule::class, $this->sut());
    }

    public function testRequestUriParamCanBeAbsent(): void
    {
        $this->prepareRawParams([]);

        $this->assertNull($this->checkRule());
    }

    public function testThrowsIfParIsRequiredGloballyButNotUsed(): void
    {
        $this->prepareRawParams([]);
        $this->moduleConfigMock->method('getRequirePushedAuthorizationRequests')->willReturn(true);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfParIsRequiredForClientButNotUsed(): void
    {
        $this->prepareRawParams([]);
        $this->moduleConfigMock->method('getRequirePushedAuthorizationRequests')->willReturn(false);
        $this->clientMock->method('getRequirePushedAuthorizationRequests')->willReturn(true);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfRequestAndRequestUriAreBothPresent(): void
    {
        $this->prepareRawParams([
            'request_uri' => self::PAR_REQUEST_URI,
            'request' => 'token',
            'client_id' => 'client123',
        ]);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfClientIdParamIsMissing(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI]);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsForInvalidRequestUriScheme(): void
    {
        $this->prepareRawParams(['request_uri' => 'urn:other:thing', 'client_id' => 'client123']);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfPushedAuthorizationRequestIsNotFound(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfPushedAuthorizationRequestIsExpired(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->parEntityMock->method('isExpired')->willReturn(true);
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn($this->parEntityMock);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfPushedAuthorizationRequestIsConsumed(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->parEntityMock->method('isExpired')->willReturn(false);
        $this->parEntityMock->method('isConsumed')->willReturn(true);
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn($this->parEntityMock);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfPushedAuthorizationRequestIsBoundToDifferentClient(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->parEntityMock->method('isExpired')->willReturn(false);
        $this->parEntityMock->method('isConsumed')->willReturn(false);
        $this->parEntityMock->method('getClientId')->willReturn('otherClient');
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn($this->parEntityMock);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsIfPushedAuthorizationRequestConsumptionFails(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->parEntityMock->method('isExpired')->willReturn(false);
        $this->parEntityMock->method('isConsumed')->willReturn(false);
        $this->parEntityMock->method('getClientId')->willReturn('client123');
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn($this->parEntityMock);
        $this->pushedAuthorizationRequestRepositoryMock->method('consume')->willReturn(false);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testCanUseValidPushedAuthorizationRequestUri(): void
    {
        $this->prepareRawParams(['request_uri' => self::PAR_REQUEST_URI, 'client_id' => 'client123']);
        $this->parEntityMock->method('isExpired')->willReturn(false);
        $this->parEntityMock->method('isConsumed')->willReturn(false);
        $this->parEntityMock->method('getClientId')->willReturn('client123');
        $this->pushedAuthorizationRequestRepositoryMock->method('find')->willReturn($this->parEntityMock);
        // Request URI is consumed at validation time (one-time use).
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())
            ->method('consume')
            ->with(self::PAR_REQUEST_URI)
            ->willReturn(true);

        $result = $this->checkRule();

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(self::PAR_REQUEST_URI, $result->getValue());
    }

    public function testThrowsForHttpsRequestUriIfParIsRequired(): void
    {
        $this->prepareRawParams(['request_uri' => self::HTTPS_REQUEST_URI, 'client_id' => 'client123']);
        $this->moduleConfigMock->method('getRequirePushedAuthorizationRequests')->willReturn(true);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testThrowsForHttpsRequestUriIfNotSupported(): void
    {
        // Override the default (true) set in setUp via a fresh module config mock.
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getRequestUriParameterSupported')->willReturn(false);

        $this->prepareRawParams(['request_uri' => self::HTTPS_REQUEST_URI, 'client_id' => 'client123']);

        $sut = new RequestUriRule(
            $this->requestParamsResolverMock,
            $this->helpers,
            $this->pushedAuthorizationRequestRepositoryMock,
            $moduleConfigMock,
        );

        $this->expectException(OidcServerException::class);
        $sut->checkRule(
            $this->requestStub,
            $this->resultBagMock,
            $this->loggerServiceMock,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsForUnresolvableHttpsRequestUri(): void
    {
        $this->prepareRawParams(['request_uri' => self::HTTPS_REQUEST_URI, 'client_id' => 'client123']);
        // Resolver could not fetch/parse (or policy denied the fetch) -> null bag.
        $this->requestParamsResolverMock->method('getRequestObjectBag')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->checkRule();
    }

    public function testCanUseResolvableHttpsRequestUri(): void
    {
        $this->prepareRawParams(['request_uri' => self::HTTPS_REQUEST_URI, 'client_id' => 'client123']);
        // Resolver produced a bag; signature/flavor validation is RequestObjectRule's job, not this rule's.
        $this->requestParamsResolverMock->method('getRequestObjectBag')
            ->willReturn($this->createMock(RequestObjectBag::class));

        $result = $this->checkRule();

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame(self::HTTPS_REQUEST_URI, $result->getValue());
    }
}
