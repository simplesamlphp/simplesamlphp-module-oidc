<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\Factories\RequestObjectFactory;
use SimpleSAML\OpenID\Core\RequestObject;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\RequestObject as RequestObjectFacade;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use SimpleSAML\OpenID\RequestObject\RequestObjectParser;

#[CoversClass(RequestParamsResolver::class)]
class RequestParamsResolverTest extends TestCase
{
    protected MockObject $helpersMock;
    protected MockObject $httpHelperMock;
    protected MockObject $coreMock;
    protected MockObject $requestMock;
    protected MockObject $requestObjectMock;
    protected MockObject $requestObjectFactoryMock;
    protected MockObject $federationMock;
    protected MockObject $psrHttpBridgeMock;
    protected MockObject $requestObjectFacadeMock;
    protected MockObject $requestObjectParserMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $clientRepositoryMock;
    protected MockObject $pushedAuthorizationRequestRepositoryMock;
    protected MockObject $loggerServiceMock;

    protected array $queryParams = [
        'a' => 'b',
    ];

    protected array $bodyParams = [
        'c' => 'd',
    ];

    protected array $requestObjectParams = [
        'e' => 'f',
    ];

    protected function setUp(): void
    {
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->httpHelperMock = $this->createMock(Helpers\Http::class);
        $this->httpHelperMock->method('getAllRequestParams')
            ->willReturn(array_merge($this->queryParams, $this->bodyParams));
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->helpersMock->method('http')->willReturn($this->httpHelperMock);
        $this->requestObjectMock = $this->createMock(RequestObject::class);
        $this->requestObjectMock->method('getPayload')->willReturn($this->requestObjectParams);
        $this->requestObjectFactoryMock = $this->createMock(RequestObjectFactory::class);
        $this->requestObjectFactoryMock->method('fromToken')->willReturn($this->requestObjectMock);
        $this->coreMock = $this->createMock(Core::class);
        $this->coreMock->method('requestObjectFactory')->willReturn($this->requestObjectFactoryMock);
        $this->federationMock = $this->createMock(Federation::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->requestObjectParserMock = $this->createMock(RequestObjectParser::class);
        $this->requestObjectFacadeMock = $this->createMock(RequestObjectFacade::class);
        $this->requestObjectFacadeMock->method('requestObjectParser')
            ->willReturn($this->requestObjectParserMock);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getRequestUriParameterSupported')->willReturn(true);
        $this->moduleConfigMock->method('getRequestUriFetchTimeout')->willReturn(5);
        $this->moduleConfigMock->method('getRequestUriMaxSizeBytes')->willReturn(102400);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }

    protected function mock(
        ?MockObject $helpersMock = null,
        ?MockObject $coreMock = null,
        ?MockObject $federationMock = null,
        ?MockObject $psrHttpBridgeMock = null,
    ): RequestParamsResolver {
        $helpersMock ??= $this->helpersMock;
        $coreMock ??= $this->coreMock;
        $federationMock ??= $this->federationMock;
        $psrHttpBridgeMock ??= $this->psrHttpBridgeMock;

        return new RequestParamsResolver(
            $helpersMock,
            $coreMock,
            $federationMock,
            $psrHttpBridgeMock,
            $this->requestObjectFacadeMock,
            $this->moduleConfigMock,
            $this->clientRepositoryMock,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->loggerServiceMock,
        );
    }

    protected function bagWithCore(): MockObject
    {
        $bag = $this->createMock(RequestObjectBag::class);
        $bag->method('get')->willReturnMap([[RequestObject::class, $this->requestObjectMock]]);

        return $bag;
    }

    protected function helpersWithParams(array $params): MockObject
    {
        $httpHelperMock = $this->createMock(Helpers\Http::class);
        $httpHelperMock->method('getAllRequestParams')->willReturn($params);
        $httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')->willReturn($params);
        $helpersMock = $this->createMock(Helpers::class);
        $helpersMock->method('http')->willReturn($httpHelperMock);

        return $helpersMock;
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RequestParamsResolver::class, $this->mock());
    }

    public function testCanGetAllFromRequest(): void
    {
        $this->assertSame(
            array_merge($this->queryParams, $this->bodyParams),
            $this->mock()->getAllFromRequest($this->requestMock),
        );
    }

    public function testCanGetAllFromRequestBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);

        $this->assertSame(
            $this->queryParams,
            $this->mock()->getAllFromRequestBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }

    public function testCanGetAllWithNoRequestObject(): void
    {
        $this->assertSame(
            array_merge($this->queryParams, $this->bodyParams),
            $this->mock()->getAll($this->requestMock),
        );
    }

    public function testCanGetAllWithRequestObject(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->requestObjectParserMock->method('fromToken')->with('token')->willReturn($this->bagWithCore());

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $this->mock($helpersMock)->getAll($this->requestMock),
        );
    }

    public function testCanGetAllBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods');
        $this->requestObjectMock->expects($this->never())->method('getPayload');

        $this->mock()->getAllBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::GET]);
    }

    public function testCanGetBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getBasedOnAllowedMethods('a', $this->requestMock),
        );
    }

    public function testCanGetAsStringBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getAsStringBasedOnAllowedMethods('a', $this->requestMock),
        );

        $this->assertNull($this->mock()->getAsStringBasedOnAllowedMethods('b', $this->requestMock));
    }

    public function testCanGetFromRequestBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn($this->queryParams);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getFromRequestBasedOnAllowedMethods('a', $this->requestMock),
        );
    }

    public function testCanGetAllWithPushedAuthorizationRequestUri(): void
    {
        $requestUri = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri];
        $helpersMock = $this->helpersWithParams($queryParams);

        $parEntityMock = $this->createMock(PushedAuthorizationRequestEntity::class);
        $parEntityMock->method('getParameters')->willReturn($this->requestObjectParams);

        // Resolution is memoized, so the repository is queried only once across repeated getAll() calls.
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())
            ->method('findValid')
            ->with($requestUri)
            ->willReturn($parEntityMock);

        $sut = $this->mock($helpersMock);

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $sut->getAll($this->requestMock),
        );
        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $sut->getAll($this->requestMock),
        );
    }

    public function testGetAllResolvesNothingForInvalidPushedAuthorizationRequestUri(): void
    {
        $requestUri = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->pushedAuthorizationRequestRepositoryMock->method('findValid')->willReturn(null);

        $this->assertSame(
            $queryParams,
            $this->mock($helpersMock)->getAll($this->requestMock),
        );
    }

    public function testGetAllSkipsRequestUriResolutionIfRequestParamIsAlsoPresent(): void
    {
        $requestUri = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'request' => 'token'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->requestObjectParserMock->method('fromToken')->willReturn($this->bagWithCore());
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('findValid');

        $this->mock($helpersMock)->getAll($this->requestMock);
    }

    public function testCanGetAllWithHttpsRequestUriForRegisteredClient(): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $clientEntityMock->method('getRequestUris')->willReturn([$requestUri]);
        $this->clientRepositoryMock->method('getClientEntity')->with('client123')->willReturn($clientEntityMock);

        // Fetch is memoized, so the request object is fetched only once across repeated getAll() calls.
        $this->requestObjectParserMock->expects($this->once())
            ->method('fromRequestUri')
            ->with($requestUri)
            ->willReturn($this->bagWithCore());

        $sut = $this->mock($helpersMock);

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $sut->getAll($this->requestMock),
        );
        $sut->getAll($this->requestMock);
    }

    public function testGetAllDoesNotFetchHttpsRequestUriIfNotRegisteredForClient(): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $clientEntityMock->method('getRequestUris')->willReturn(['https://client.example.org/other.jwt']);
        $this->clientRepositoryMock->method('getClientEntity')->willReturn($clientEntityMock);

        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame($queryParams, $this->mock($helpersMock)->getAll($this->requestMock));
    }

    public function testGetAllDoesNotFetchHttpsRequestUriIfNotSupported(): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getRequestUriParameterSupported')->willReturn(false);
        $this->moduleConfigMock = $moduleConfigMock;

        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame($queryParams, $this->mock($helpersMock)->getAll($this->requestMock));
    }

    public function testCanFetchHttpsRequestUriForFederationClient(): void
    {
        $requestUri = 'https://rp.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'https://rp.example.org'];
        $helpersMock = $this->helpersWithParams($queryParams);

        // Federation candidate: client not in storage, federation enabled, request_uri allowed (null = allow
        // any) -> fetch is allowed (trust is validated after the fetch, in ClientRule).
        $this->clientRepositoryMock->method('getClientEntity')->willReturn(null);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getFederationRequestUriAllowedPrefixes')->willReturn(null);

        $this->requestObjectParserMock->expects($this->once())
            ->method('fromRequestUri')
            ->with($requestUri)
            ->willReturn($this->bagWithCore());

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $this->mock($helpersMock)->getAll($this->requestMock),
        );
    }

    public function testCanFetchHttpsRequestUriForFederationClientWithAllowedPrefix(): void
    {
        $requestUri = 'https://rp.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'https://rp.example.org'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->clientRepositoryMock->method('getClientEntity')->willReturn(null);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getFederationRequestUriAllowedPrefixes')
            ->willReturn(['https://rp.example.org/']);

        $this->requestObjectParserMock->expects($this->once())
            ->method('fromRequestUri')
            ->with($requestUri)
            ->willReturn($this->bagWithCore());

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $this->mock($helpersMock)->getAll($this->requestMock),
        );
    }

    public function testDoesNotFetchHttpsRequestUriForFederationClientWithDisallowedPrefix(): void
    {
        $requestUri = 'https://attacker.example.org/request-object.jwt';
        $queryParams = [
            ...$this->queryParams,
            'request_uri' => $requestUri,
            'client_id' => 'https://attacker.example.org',
        ];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->clientRepositoryMock->method('getClientEntity')->willReturn(null);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getFederationRequestUriAllowedPrefixes')
            ->willReturn(['https://rp.example.org/']);

        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame($queryParams, $this->mock($helpersMock)->getAll($this->requestMock));
    }

    public function testDoesNotFetchHttpsRequestUriForFederationClientWhenPrefixListIsEmpty(): void
    {
        $requestUri = 'https://rp.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'https://rp.example.org'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->clientRepositoryMock->method('getClientEntity')->willReturn(null);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        // Empty allowlist (the default) denies all federation-candidate fetches.
        $this->moduleConfigMock->method('getFederationRequestUriAllowedPrefixes')->willReturn([]);

        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame($queryParams, $this->mock($helpersMock)->getAll($this->requestMock));
    }

    public function testDoesNotFetchHttpsRequestUriForUnknownClientWhenFederationDisabled(): void
    {
        $requestUri = 'https://rp.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'https://rp.example.org'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $this->clientRepositoryMock->method('getClientEntity')->willReturn(null);
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(false);

        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame($queryParams, $this->mock($helpersMock)->getAll($this->requestMock));
    }

    public function testGetRequestObjectBagForRequestParam(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        $helpersMock = $this->helpersWithParams($queryParams);

        $bag = $this->bagWithCore();
        $this->requestObjectParserMock->method('fromToken')->with('token')->willReturn($bag);

        $this->assertSame(
            $bag,
            $this->mock($helpersMock)->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }

    public function testGetRequestObjectBagReturnsNullForParUrn(): void
    {
        $requestUri = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri];

        $this->assertNull(
            $this->mock($this->helpersWithParams($queryParams))
                ->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }

    public function testGetRequestObjectBagReturnsNullWhenNoSource(): void
    {
        $this->assertNull(
            $this->mock($this->helpersWithParams($this->queryParams))
                ->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }
}
