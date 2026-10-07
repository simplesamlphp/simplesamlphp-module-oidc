<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\AccessTokenController;
use SimpleSAML\Module\oidc\Controllers\Traits\RequestTrait;
use SimpleSAML\Module\oidc\Repositories\AllowedOriginRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\OAuth2\DpopProof;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Throwable;

#[CoversClass(AccessTokenController::class)]
#[AllowMockObjectsWithoutExpectations]
class AccessTokenControllerTest extends TestCase
{
    protected MockObject $authorizationServerMock;

    protected MockObject $allowedOriginRepository;

    protected MockObject $serverRequestMock;

    protected MockObject $responseMock;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $errorResponderMock;

    protected MockObject $requestFactoryMock;

    protected MockObject $responseFactoryMock;

    protected MockObject $symfonyRequestMock;

    protected MockObject $symfonyResponseMock;

    protected MockObject $httpFoundationFactoryMock;

    protected MockObject $responseHeaderBagMock;

    protected MockObject $dpopProofVerifierMock;

    protected MockObject $routesMock;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->authorizationServerMock = $this->createMock(AuthorizationServer::class);
        $this->allowedOriginRepository = $this->createMock(AllowedOriginRepository::class);
        $this->serverRequestMock = $this->createMock(ServerRequest::class);
        $this->responseMock = $this->createMock(Response::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);

        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);

        $this->symfonyRequestMock = $this->createMock(Request::class);
        $this->symfonyResponseMock = $this->createMock(\Symfony\Component\HttpFoundation\Response::class);
        $this->responseHeaderBagMock = $this->createMock(ResponseHeaderBag::class);
        $this->symfonyResponseMock->headers = $this->responseHeaderBagMock;

        $this->httpFoundationFactoryMock = $this->createMock(HttpFoundationFactory::class);
        $this->httpFoundationFactoryMock->method('createResponse')->willReturn($this->symfonyResponseMock);
        $this->psrHttpBridgeMock->method('getHttpFoundationFactory')->willReturn($this->httpFoundationFactoryMock);

        $this->dpopProofVerifierMock = $this->createMock(DpopProofVerifier::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlToken')->willReturn('https://op.example.org/oidc/token');
    }


    protected function mock(): AccessTokenController
    {
        return new AccessTokenController(
            $this->authorizationServerMock,
            $this->allowedOriginRepository,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
            $this->dpopProofVerifierMock,
            $this->routesMock,
        );
    }


    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AccessTokenController::class,
            $this->mock(),
        );
    }


    /**
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testItRespondsToAccessTokenRequest(): void
    {
        $markedRequestMock = $this->createMock(ServerRequest::class);
        $this->serverRequestMock->expects($this->once())->method('withAttribute')
            ->with(RequestParamsResolver::ATTRIBUTE_OWN_PARAMS_ONLY, true)
            ->willReturn($markedRequestMock);
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->with($this->identicalTo($markedRequestMock), $this->isInstanceOf(ResponseInterface::class))
            ->willReturn($this->responseMock);

        $this->assertSame(
            $this->responseMock,
            $this->mock()->__invoke($this->serverRequestMock),
        );
    }


    /**
     * A preflight from an allowed origin is answered with the CORS headers, the `DPoP` request header allowed for
     * a client which sends a proof (RFC 9449).
     */
    public function testItHandlesCorsRequest(): void
    {
        $this->serverRequestMock->expects($this->once())->method('getMethod')->willReturn('OPTIONS');
        $this->serverRequestMock->expects($this->once())->method('getHeaderLine')->with('Origin')
        ->willReturn('http://localhost');
        $this->allowedOriginRepository->expects($this->once())->method('has')
            ->with('http://localhost')
            ->willReturn(true);

        $headers = [];
        $this->responseMock->expects($this->atLeast(4))->method('withHeader')
            ->willReturnCallback(function (string $name, string $value) use (&$headers): Response {
                $headers[$name] = $value;

                return $this->responseMock;
            });
        $this->responseMock->method('withBody')->willReturnSelf();

        $this->mock()->__invoke($this->serverRequestMock);

        $this->assertSame('http://localhost', $headers['Access-Control-Allow-Origin'] ?? null);
        $this->assertSame('Authorization, X-Requested-With, DPoP', $headers['Access-Control-Allow-Headers'] ?? null);
    }


    public function testItAlwaysReturnsAccessControlAllowOrigin(): void
    {
        $this->authorizationServerMock
            ->expects($this->once())
            ->method('respondToAccessTokenRequest')
            ->willReturn($this->responseMock);

        $set = [];
        $this->responseHeaderBagMock->method('set')->willReturnCallback(
            function (string $key, mixed $values) use (&$set): void {
                $set[$key] = $values;
            },
        );

        $this->mock()->token($this->symfonyRequestMock);

        $this->assertSame(
            ['Access-Control-Allow-Origin' => '*', 'Access-Control-Expose-Headers' => 'WWW-Authenticate'],
            $set,
        );
    }


    /**
     * @return array<string,array{0:\Throwable}>
     */
    public static function failureProvider(): array
    {
        return [
            'an OAuth error' => [OidcServerException::invalidRequest('code')],
            'a failure of the OP\'s own' => [new RuntimeException('Database error')],
        ];
    }


    /**
     * A refusal carries the CORS headers too, so that a JavaScript client can read why it was refused, the
     * challenge included (RFC 9449 section 7.1).
     */
    #[DataProvider('failureProvider')]
    public function testAnswersARefusalWithTheCorsHeaders(Throwable $failure): void
    {
        $this->authorizationServerMock->method('respondToAccessTokenRequest')->willThrowException($failure);
        $this->errorResponderMock->method('forException')
            ->willReturn(new SymfonyResponse('{"error":"invalid_request"}', 400));

        $response = $this->mock()->token(Request::create('https://op.example.org/oidc/token', 'POST'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame('WWW-Authenticate', $response->headers->get('Access-Control-Expose-Headers'));
    }


    /**
     * A refused preflight gets no CORS headers: a preflight passes only with a success status, so they would
     * grant nothing, and an origin which is not allowed is not told otherwise.
     */
    public function testAnswersARefusedPreflightWithoutTheCorsHeaders(): void
    {
        $psrRequest = new ServerRequest('OPTIONS', 'https://op.example.org/oidc/token');
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->method('createRequest')->willReturn($psrRequest);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);
        $this->errorResponderMock->expects($this->once())->method('forException')
            ->willReturn(new SymfonyResponse('{"error":"request_not_supported"}', 400));

        $response = $this->mock()->token(Request::create('https://op.example.org/oidc/token', 'OPTIONS'));

        $this->assertSame(400, $response->getStatusCode());
        $this->assertFalse($response->headers->has('Access-Control-Allow-Origin'));
        $this->assertFalse($response->headers->has('Access-Control-Expose-Headers'));
    }


    public function testTokenAnswersAnOAuthErrorThroughTheErrorResponder(): void
    {
        $exception = OidcServerException::accessDenied('Client authentication failed.');
        $this->authorizationServerMock->method('respondToAccessTokenRequest')->willThrowException($exception);
        $this->errorResponderMock->expects($this->once())->method('forException')
            ->with($exception)
            ->willReturn($this->symfonyResponseMock);

        $this->assertSame($this->symfonyResponseMock, $this->mock()->token($this->symfonyRequestMock));
    }


    /**
     * A failure of the OP's own - the database did not answer while the client was being authenticated -
     * is answered as `server_error` in the token error format, not left to SimpleSAMLphp's HTML error page.
     * The client is told nothing of the cause, which travels only as the previous exception, for the log.
     */
    public function testTokenAnswersAFailureOfTheOpsOwnAsAServerError(): void
    {
        $failure = new RuntimeException('Database error: SQLSTATE[HY000] [2002] Connection refused');
        $this->authorizationServerMock->method('respondToAccessTokenRequest')->willThrowException($failure);
        $this->errorResponderMock->expects($this->once())->method('forException')
            ->with($this->callback(
                static fn(Throwable $exception): bool =>
                    $exception instanceof OidcServerException &&
                    $exception->getErrorType() === 'server_error' &&
                    $exception->getHttpStatusCode() === 500 &&
                    $exception->getPrevious() === $failure &&
                    !str_contains($exception->getMessage(), 'Connection refused') &&
                    $exception->getHint() === null,
            ))
            ->willReturn($this->symfonyResponseMock);

        $this->assertSame($this->symfonyResponseMock, $this->mock()->token($this->symfonyRequestMock));
    }


    /**
     * Every DPoP proof the token endpoint receives is checked (RFC 9449 section 5), against the token endpoint URL
     * this OP publishes and with no access token, before any grant runs. The proof which passed travels to the
     * grants on the request, which bind what they issue to its key.
     */
    public function testChecksTheDpopProofAndHandsItToTheGrantsOnTheRequest(): void
    {
        $request = new ServerRequest('POST', 'https://op.example.org/oidc/token');
        $verifiedDpopProof = new VerifiedDpopProof($this->createStub(DpopProof::class), 'thumbprint-of-the-key');
        $this->dpopProofVerifierMock->expects($this->once())->method('verify')
            ->with($request, 'https://op.example.org/oidc/token', null)
            ->willReturn($verifiedDpopProof);
        $this->authorizationServerMock->expects($this->once())->method('respondToAccessTokenRequest')
            ->with(
                $this->callback(
                    fn(ServerRequest $handed): bool => $handed->getAttribute(
                        DpopProofVerifier::ATTRIBUTE_VERIFIED_PROOF,
                    ) === $verifiedDpopProof && $handed->getMethod() === 'POST' &&
                    $handed->getAttribute(RequestParamsResolver::ATTRIBUTE_OWN_PARAMS_ONLY) === true,
                ),
                $this->isInstanceOf(ResponseInterface::class),
            )
            ->willReturn($this->responseMock);

        $this->assertSame($this->responseMock, $this->mock()->__invoke($request));
    }


    /**
     * A request without a DPoP header reaches the grants with no proof on it. Like every token request, it is
     * marked to be read as it was sent, not as an authorization request with a Request Object or a request_uri
     * (RequestParamsResolver).
     */
    public function testHandsARequestWithoutAProofToTheGrantsReadAsItWasSent(): void
    {
        $request = new ServerRequest('POST', 'https://op.example.org/oidc/token');
        $this->dpopProofVerifierMock->expects($this->once())->method('verify')->willReturn(null);
        $this->authorizationServerMock->expects($this->once())->method('respondToAccessTokenRequest')
            ->with(
                $this->callback(
                    fn(ServerRequest $handed): bool => $handed->getAttributes() === [
                        RequestParamsResolver::ATTRIBUTE_OWN_PARAMS_ONLY => true,
                    ] && $handed->getUri() === $request->getUri(),
                ),
                $this->isInstanceOf(ResponseInterface::class),
            )
            ->willReturn($this->responseMock);

        $this->assertSame($this->responseMock, $this->mock()->__invoke($request));
    }


    /**
     * A proof which fails a check refuses the request as `invalid_dpop_proof` before any grant runs: no code, no
     * refresh token and no Credential Offer is looked at for it.
     */
    public function testRefusesAnInvalidProofBeforeAnyGrantRuns(): void
    {
        $refusal = OidcServerException::invalidDpopProof('The DPoP proof signature does not verify with its key.');
        $this->dpopProofVerifierMock->method('verify')->willThrowException($refusal);
        $this->authorizationServerMock->expects($this->never())->method('respondToAccessTokenRequest');

        try {
            $this->mock()->__invoke(new ServerRequest('POST', 'https://op.example.org/oidc/token'));
            $this->fail('The request must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame($refusal, $exception);
            $this->assertSame(400, $exception->getHttpStatusCode());
        }
    }


    /**
     * A preflight carries no proof to check: it is answered by the CORS handling alone.
     */
    public function testChecksNoProofOnAPreflight(): void
    {
        $this->dpopProofVerifierMock->expects($this->never())->method('verify');
        $this->allowedOriginRepository->method('has')->willReturn(true);
        $this->responseMock->method('withHeader')->willReturnSelf();
        $this->responseMock->method('withBody')->willReturnSelf();

        $request = (new ServerRequest('OPTIONS', 'https://op.example.org/oidc/token'))
            ->withHeader('Origin', 'http://localhost');

        $this->mock()->__invoke($request);
    }


    public function testItUsesRequestTrait(): void
    {
        $this->assertContains(RequestTrait::class, class_uses(AccessTokenController::class));
    }
}
