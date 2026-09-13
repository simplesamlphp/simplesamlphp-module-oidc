<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Utils;

use Exception;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\RegistrationTypeEnum;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Core\ClientAssertion;
use SimpleSAML\OpenID\Core\Factories\ClientAssertionFactory;
use SimpleSAML\OpenID\Core\Factories\RequestObjectFactory;
use SimpleSAML\OpenID\Core\RequestObject;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Factories\RequestObjectFactory as FederationRequestObjectFactory;
use SimpleSAML\OpenID\Federation\RequestObject as FederationRequestObject;
use SimpleSAML\OpenID\RequestObject as RequestObjectFacade;
use SimpleSAML\OpenID\RequestObject\RequestObjectBag;
use SimpleSAML\OpenID\RequestObject\RequestObjectParser;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(RequestParamsResolver::class)]
#[AllowMockObjectsWithoutExpectations]
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
        $this->httpHelperMock = $this->createMock(Http::class);
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


    /**
     * A bag whose OpenID Connect Core request object carries the given payload.
     */
    protected function bagWithCorePayload(array $payload): MockObject
    {
        $requestObjectMock = $this->createMock(RequestObject::class);
        $requestObjectMock->method('getPayload')->willReturn($payload);
        $bag = $this->createMock(RequestObjectBag::class);
        $bag->method('get')->willReturnMap([[RequestObject::class, $requestObjectMock]]);

        return $bag;
    }


    protected function helpersWithParams(array $params): MockObject
    {
        $httpHelperMock = $this->createMock(Http::class);
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


    public function testCanGetAllBasedOnAllowedMethodsIncludingTheRequestObject(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods')
            ->with($this->identicalTo($this->requestMock), [HttpMethodsEnum::POST])->willReturn($queryParams);
        $this->httpHelperMock->expects($this->never())->method('getAllRequestParams');
        $this->requestObjectParserMock->method('fromToken')->with('token')->willReturn($this->bagWithCore());

        $this->assertSame(
            array_merge($queryParams, $this->requestObjectParams),
            $this->mock()->getAllBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::POST]),
        );
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
            ->willReturn([...$this->queryParams, 'n' => 5]);
        $this->assertSame(
            $this->queryParams['a'],
            $this->mock()->getAsStringBasedOnAllowedMethods('a', $this->requestMock),
        );
        $this->assertSame('5', $this->mock()->getAsStringBasedOnAllowedMethods('n', $this->requestMock));

        $this->assertNull($this->mock()->getAsStringBasedOnAllowedMethods('b', $this->requestMock));
    }


    public function testCanGetFromRequestBasedOnAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')
            ->willReturn([...$this->queryParams, 'request' => 'token']);
        $this->requestObjectParserMock->expects($this->never())->method('fromToken');
        $sut = $this->mock();

        $this->assertSame($this->queryParams['a'], $sut->getFromRequestBasedOnAllowedMethods('a', $this->requestMock));
        // Not from the request object, which holds an 'e'.
        $this->assertNull($sut->getFromRequestBasedOnAllowedMethods('e', $this->requestMock));
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
            ->with($requestUri, 5, 102400)
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
            ->with($requestUri, 5, 102400)
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
            ->with($requestUri, 5, 102400)
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


    public function testBridgesASymfonyRequestBeforeReadingItsParams(): void
    {
        $symfonyRequest = new Request();
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')
            ->willReturn($this->psrHttpFactoryBridging($symfonyRequest));
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParams')
            ->with($this->identicalTo($this->requestMock));

        $this->assertSame(
            array_merge($this->queryParams, $this->bodyParams),
            $this->mock()->getAllFromRequest($symfonyRequest),
        );
    }


    public function testBridgesASymfonyRequestBeforeReadingItsParamsForTheAllowedMethods(): void
    {
        $symfonyRequest = new Request();
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')
            ->willReturn($this->psrHttpFactoryBridging($symfonyRequest));
        $this->httpHelperMock->expects($this->once())->method('getAllRequestParamsBasedOnAllowedMethods')
            ->with($this->identicalTo($this->requestMock), [HttpMethodsEnum::POST])->willReturn($this->bodyParams);

        $this->assertSame(
            $this->bodyParams,
            $this->mock()->getAllFromRequestBasedOnAllowedMethods($symfonyRequest, [HttpMethodsEnum::POST]),
        );
    }


    /**
     * The helper answers null for a request whose method is not among the allowed ones (or carries no usable
     * body); the resolver turns that into no params.
     */
    public function testAnswersNoParamsWhenTheHelperHasNoneForTheAllowedMethods(): void
    {
        $this->httpHelperMock->method('getAllRequestParamsBasedOnAllowedMethods')->willReturn(null);

        $this->assertSame(
            [],
            $this->mock()->getAllFromRequestBasedOnAllowedMethods($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }


    public function testGetsOneParamFromTheRequestOrTheRequestObject(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        $this->requestObjectParserMock->method('fromToken')->with('token')->willReturn($this->bagWithCore());
        $sut = $this->mock($this->helpersWithParams($queryParams));

        $this->assertSame('b', $sut->get('a', $this->requestMock));
        $this->assertSame('f', $sut->get('e', $this->requestMock));
        $this->assertNull($sut->get('missing', $this->requestMock));
    }


    /**
     * OpenID Connect Core 1.0, section 6.1: when the request parameter is used, the request parameter values
     * contained in the JWT supersede those passed using the OAuth 2.0 request syntax.
     */
    public function testTheRequestObjectPassedByValueSupersedesARequestParamOfTheSameName(): void
    {
        $queryParams = ['a' => 'from the request', 'request' => 'token'];
        $this->requestObjectParserMock->method('fromToken')->with('token')
            ->willReturn($this->bagWithCorePayload(['a' => 'from the request object']));

        $this->assertSame(
            ['a' => 'from the request object', 'request' => 'token'],
            $this->mock($this->helpersWithParams($queryParams))->getAll($this->requestMock),
        );
    }


    /**
     * OpenID Connect Core 1.0, section 6.2: when the request_uri parameter is used, the request parameter
     * values contained in the referenced JWT supersede those passed using the OAuth 2.0 request syntax.
     */
    public function testTheRequestObjectPassedByReferenceSupersedesARequestParamOfTheSameName(): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = ['a' => 'from the request', 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $this->clientRepositoryMock->method('getClientEntity')->with('client123')
            ->willReturn($this->registeredClientWith([$requestUri]));
        $this->requestObjectParserMock->method('fromRequestUri')->with($requestUri, 5, 102400)
            ->willReturn($this->bagWithCorePayload(['a' => 'from the request object']));

        $this->assertSame(
            ['a' => 'from the request object', 'request_uri' => $requestUri, 'client_id' => 'client123'],
            $this->mock($this->helpersWithParams($queryParams))->getAll($this->requestMock),
        );
    }


    /**
     * The library's parser does not throw for a token no flavor accepts; it answers a bag holding nothing,
     * and the resolver takes that as no params, without a warning.
     */
    public function testResolvesNothingWhenTheRequestObjectParsesAsNoFlavor(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        $this->requestObjectParserMock->method('fromToken')->with('token')->willReturn(new RequestObjectBag());
        $this->loggerServiceMock->expects($this->never())->method('warning');

        $this->assertSame(
            $queryParams,
            $this->mock($this->helpersWithParams($queryParams))->getAll($this->requestMock),
        );
    }


    public function testResolvesNothingAndWarnsOnceWhenThePushedAuthorizationRequestLookupFails(): void
    {
        $requestUri = PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri];
        // Memoized as empty, so the repository is asked once across repeated getAll() calls.
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('findValid')
            ->with($requestUri)->willThrowException(new Exception('store is down'));
        $this->loggerServiceMock->expects($this->once())->method('warning')->with(
            'RequestParamsResolver: error resolving pushed authorization request: store is down',
            ['requestUri' => $requestUri],
        );
        $sut = $this->mock($this->helpersWithParams($queryParams));

        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
    }


    public function testResolvesNothingAndWarnsOnceWhenTheRequestObjectParserThrows(): void
    {
        $queryParams = [...$this->queryParams, 'request' => 'token'];
        // Memoized as failed, so the parser is asked once across repeated getAll() calls.
        $this->requestObjectParserMock->expects($this->once())->method('fromToken')
            ->with('token')->willThrowException(new Exception('not a JWT'));
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with('RequestParamsResolver: error parsing request object: not a JWT', []);
        $sut = $this->mock($this->helpersWithParams($queryParams));

        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
        $this->assertNull($sut->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]));
    }


    public function testResolvesNothingAndWarnsOnceWhenTheRequestUriCannotBeFetched(): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $this->clientRepositoryMock->method('getClientEntity')->with('client123')
            ->willReturn($this->registeredClientWith([$requestUri]));
        // Memoized as unfetchable, so the parser is asked once across repeated getAll() calls.
        $this->requestObjectParserMock->expects($this->once())->method('fromRequestUri')
            ->with($requestUri, 5, 102400)->willThrowException(new Exception('connection refused'));
        $this->loggerServiceMock->expects($this->once())->method('warning')->with(
            'RequestParamsResolver: error fetching request object from request_uri: connection refused',
            ['requestUri' => $requestUri],
        );
        $sut = $this->mock($this->helpersWithParams($queryParams));

        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
        $this->assertSame($queryParams, $sut->getAll($this->requestMock));
        $this->assertNull($sut->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]));
    }


    #[DataProvider('unusableClientIdProvider')]
    public function testDoesNotFetchHttpsRequestUriWithoutAUsableClientId(array $clientIdParam): void
    {
        $requestUri = 'https://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, ...$clientIdParam];
        $this->clientRepositoryMock->expects($this->never())->method('getClientEntity');
        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertSame(
            $queryParams,
            $this->mock($this->helpersWithParams($queryParams))->getAll($this->requestMock),
        );
    }


    public static function unusableClientIdProvider(): array
    {
        return ['absent' => [[]], 'empty' => [['client_id' => '']], 'not a string' => [['client_id' => 123]]];
    }


    #[DataProvider('httpsSchemeProvider')]
    public function testGetRequestObjectBagFetchesAnHttpsRequestUri(string $requestUri): void
    {
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $this->clientRepositoryMock->method('getClientEntity')->with('client123')
            ->willReturn($this->registeredClientWith([$requestUri]));
        $bag = $this->bagWithCore();
        $this->requestObjectParserMock->expects($this->once())->method('fromRequestUri')
            ->with($requestUri, 5, 102400)->willReturn($bag);

        $this->assertSame(
            $bag,
            $this->mock($this->helpersWithParams($queryParams))
                ->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }


    public static function httpsSchemeProvider(): array
    {
        return [
            'lower case' => ['https://client.example.org/request-object.jwt'],
            'upper case' => ['HTTPS://client.example.org/request-object.jwt'],
        ];
    }


    public function testGetRequestObjectBagReturnsNullForARequestUriWhichIsNotHttps(): void
    {
        // Registered for the client and otherwise fetchable, so that only the scheme stands in the way.
        $requestUri = 'http://client.example.org/request-object.jwt';
        $queryParams = [...$this->queryParams, 'request_uri' => $requestUri, 'client_id' => 'client123'];
        $this->clientRepositoryMock->method('getClientEntity')->willReturn($this->registeredClientWith([$requestUri]));
        $this->requestObjectParserMock->expects($this->never())->method('fromRequestUri');

        $this->assertNull(
            $this->mock($this->helpersWithParams($queryParams))
                ->getRequestObjectBag($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }


    public function testParsesARequestObjectTokenAsOpenIdCore(): void
    {
        $this->requestObjectFactoryMock->expects($this->once())->method('fromToken')->with('token');

        $this->assertSame($this->requestObjectMock, $this->mock()->parseRequestObjectToken('token'));
    }


    public function testParsesARequestObjectTokenAsOpenIdFederation(): void
    {
        $federationRequestObject = $this->createStub(FederationRequestObject::class);
        $federationRequestObjectFactoryMock = $this->createMock(FederationRequestObjectFactory::class);
        $federationRequestObjectFactoryMock->expects($this->once())->method('fromToken')
            ->with('token')->willReturn($federationRequestObject);
        $this->federationMock->method('requestObjectFactory')->willReturn($federationRequestObjectFactoryMock);

        $this->assertSame($federationRequestObject, $this->mock()->parseFederationRequestObjectToken('token'));
    }


    public function testParsesAClientAssertionToken(): void
    {
        $clientAssertion = $this->createStub(ClientAssertion::class);
        $clientAssertionFactoryMock = $this->createMock(ClientAssertionFactory::class);
        $clientAssertionFactoryMock->expects($this->once())->method('fromToken')
            ->with('assertion')->willReturn($clientAssertion);
        $this->coreMock->method('clientAssertionFactory')->willReturn($clientAssertionFactoryMock);

        $this->assertSame($clientAssertion, $this->mock()->parseClientAssertionToken('assertion'));
    }


    /**
     * A VCI authorization code request is recognised by response_type "code" together with an issuer_state,
     * which only that flow carries. The issuer_state is read as a string, so a scalar of any type counts.
     */
    #[DataProvider('vciAuthorizationCodeRequestProvider')]
    public function testTellsAVciAuthorizationCodeRequestByResponseTypeAndIssuerState(
        array $params,
        bool $isVciAuthorizationCodeRequest,
    ): void {
        $this->assertSame(
            $isVciAuthorizationCodeRequest,
            $this->mock($this->helpersWithParams($params))
                ->isVciAuthorizationCodeRequest($this->requestMock, [HttpMethodsEnum::GET]),
        );
    }


    public static function vciAuthorizationCodeRequestProvider(): array
    {
        return [
            'code with an issuer state' => [['response_type' => 'code', 'issuer_state' => 'state123'], true],
            'code with a numeric issuer state' => [['response_type' => 'code', 'issuer_state' => 123], true],
            'code without an issuer state' => [['response_type' => 'code'], false],
            'another response type with an issuer state' => [
                ['response_type' => 'id_token', 'issuer_state' => 'state123'],
                false,
            ],
            // Not a duplicate of the two negatives above: a rewrite which answers true for an empty request,
            // or compares the two conditions for equality, passes both of them and fails this one.
            'nothing at all' => [[], false],
        ];
    }


    public function testTellsAVciAuthorizationCodeRequestFromTheAllowedMethodsOnly(): void
    {
        $this->httpHelperMock->expects($this->atLeastOnce())->method('getAllRequestParamsBasedOnAllowedMethods')
            ->with($this->identicalTo($this->requestMock), [HttpMethodsEnum::POST])
            ->willReturn(['response_type' => 'code', 'issuer_state' => 'state123']);
        $this->httpHelperMock->expects($this->never())->method('getAllRequestParams');

        $this->assertTrue($this->mock()->isVciAuthorizationCodeRequest($this->requestMock, [HttpMethodsEnum::POST]));
    }


    /**
     * A PSR-7 factory which turns exactly the given Symfony request into the request mock.
     */
    protected function psrHttpFactoryBridging(Request $symfonyRequest): MockObject
    {
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->expects($this->once())->method('createRequest')
            ->with($this->identicalTo($symfonyRequest))->willReturn($this->requestMock);

        return $psrHttpFactoryMock;
    }


    /**
     * A manually registered client with the given request_uris.
     */
    protected function registeredClientWith(array $requestUris): MockObject
    {
        $clientEntityMock = $this->createMock(ClientEntityInterface::class);
        $clientEntityMock->method('getRegistrationType')->willReturn(RegistrationTypeEnum::Manual);
        $clientEntityMock->method('getRequestUris')->willReturn($requestUris);

        return $clientEntityMock;
    }
}
