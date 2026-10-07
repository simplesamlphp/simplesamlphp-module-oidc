<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use DateTimeImmutable;
use DateTimeZone;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\PushedAuthorizationController;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Factories\Entities\PushedAuthorizationRequestEntityFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AuthorizationDetailsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\DpopJktRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IssuerStateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\OfferedCredentialsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\Validators\DpopProofVerifier;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\Module\oidc\ValueAbstracts\VerifiedDpopProof;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;
use SimpleSAML\OpenID\OAuth2\DpopProof;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(PushedAuthorizationController::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[UsesClass(ResolvedClientAuthenticationMethod::class)]
#[AllowMockObjectsWithoutExpectations]
class PushedAuthorizationControllerTest extends TestCase
{
    protected MockObject $authenticatedOAuth2ClientResolverMock;

    protected MockObject $pushedAuthorizationRequestRepositoryMock;

    protected MockObject $pushedAuthorizationRequestEntityFactoryMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $errorResponderMock;

    protected Helpers $helpers;

    protected MockObject $loggerMock;

    protected MockObject $serverRequestMock;

    protected MockObject $responseMock;

    protected MockObject $responseFactoryMock;

    protected MockObject $streamMock;

    protected MockObject $clientMock;

    protected MockObject $parEntityMock;

    protected MockObject $resultBagMock;

    protected MockObject $dpopProofVerifierMock;

    protected MockObject $routesMock;


    protected function setUp(): void
    {
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->pushedAuthorizationRequestEntityFactoryMock = $this->createMock(
            PushedAuthorizationRequestEntityFactory::class,
        );
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
        $this->helpers = new Helpers();
        $this->loggerMock = $this->createMock(LoggerService::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->responseMock = $this->createMock(ResponseInterface::class);
        $this->responseFactoryMock = $this->createMock(ResponseFactoryInterface::class);
        $this->streamMock = $this->createMock(StreamInterface::class);

        $this->responseMock->method('getBody')->willReturn($this->streamMock);
        $this->responseMock->method('withStatus')->willReturn($this->responseMock);
        $this->responseMock->method('withHeader')->willReturn($this->responseMock);
        $this->responseFactoryMock->method('createResponse')->willReturn($this->responseMock);
        $this->psrHttpBridgeMock->method('getResponseFactory')->willReturn($this->responseFactoryMock);

        $this->clientMock = $this->createMock(ClientEntityInterface::class);
        $this->clientMock->method('getIdentifier')->willReturn('client123');

        $this->parEntityMock = $this->createMock(PushedAuthorizationRequestEntity::class);
        $this->parEntityMock->method('getRequestUri')
            ->willReturn(PushedAuthorizationRequestEntityFactory::REQUEST_URI_PREFIX . 'abc123');
        $this->parEntityMock->method('getExpiresAt')
            ->willReturn(new DateTimeImmutable('+5 minutes', new DateTimeZone('UTC')));

        $this->resultBagMock = $this->createMock(ResultBag::class);
        $this->requestRulesManagerMock->method('check')->willReturn($this->resultBagMock);

        $this->dpopProofVerifierMock = $this->createMock(DpopProofVerifier::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlPushedAuthorizationRequest')->willReturn('https://op.example.org/oidc/par');
    }


    protected function sut(): PushedAuthorizationController
    {
        return new PushedAuthorizationController(
            $this->authenticatedOAuth2ClientResolverMock,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->pushedAuthorizationRequestEntityFactoryMock,
            $this->requestRulesManagerMock,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
            $this->helpers,
            $this->loggerMock,
            $this->dpopProofVerifierMock,
            $this->routesMock,
        );
    }


    protected function prepareAuthenticatedClient(
        ClientAuthenticationMethodsEnum $method = ClientAuthenticationMethodsEnum::ClientSecretPost,
    ): void {
        $resolvedAuth = new ResolvedClientAuthenticationMethod($this->clientMock, $method);
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn($resolvedAuth);
    }


    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(PushedAuthorizationController::class, $this->sut());
    }


    public function testMethodMustBePost(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('GET');

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(405)->willReturn($this->responseMock);
        $this->responseMock->expects($this->once())->method('withHeader')
            ->with('Allow', 'POST')->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }


    public function testClientAuthenticationFailureThrows(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testConfidentialClientMustAuthenticate(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->clientMock->method('isConfidential')->willReturn(true);
        $this->prepareAuthenticatedClient(ClientAuthenticationMethodsEnum::None);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testRejectsRequestUriInBody(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn([
            'request_uri' => 'some-uri',
        ]);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testRejectsClientIdParamWhichDoesNotMatchAuthenticatedClient(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn([
            'client_id' => 'otherClient',
        ]);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testHandlesValidParRequest(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $params = [
            'client_id' => 'client123',
            'client_secret' => 'verysecret',
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
            'scope' => 'openid',
            'state' => 'xyz',
        ];
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);

        // Client authentication params must not be persisted, while client_id is bound to the
        // authenticated client.
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->with(
                'client123',
                [
                    'client_id' => 'client123',
                    'redirect_uri' => 'https://localhost/callback',
                    'response_type' => 'code',
                    'scope' => 'openid',
                    'state' => 'xyz',
                ],
            )
            ->willReturn($this->parEntityMock);

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('persist')
            ->with($this->parEntityMock);

        $this->responseMock->expects($this->once())->method('withStatus')
            ->with(201)->willReturn($this->responseMock);

        $response = $this->sut()->__invoke($this->serverRequestMock);
        $this->assertSame($this->responseMock, $response);
    }


    /**
     * A pushed request which follows a Credential Offer is checked for an offer which can still be redeemed, and
     * for asking only for what the offer offered, as the authorization endpoint checks them. The rules read the
     * state, the redirect URI, the issuer state, the scopes and the authorization details from the result bag,
     * so each has to run after the rules which put them there.
     */
    public function testChecksTheIssuerStateAfterTheRulesItReadsFrom(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->serverRequestMock->method('getParsedBody')->willReturn(['response_type' => 'code']);
        $this->prepareAuthenticatedClient();
        $this->pushedAuthorizationRequestEntityFactoryMock->method('fromData')->willReturn($this->parEntityMock);
        // The scopes ScopeRule found for a request without a scope parameter: none.
        $this->resultBagMock->method('getOrFail')->willReturn(new Result(ScopeRule::class, []));

        $checkedRules = null;
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->expects($this->once())->method('check')->willReturnCallback(
            function (ServerRequestInterface $request, array $rules) use (&$checkedRules): ResultBag {
                $checkedRules = $rules;

                return $this->resultBagMock;
            },
        );

        $this->sut()->__invoke($this->serverRequestMock);

        $this->assertIsArray($checkedRules);
        $position = array_search(IssuerStateRule::class, $checkedRules, true);
        $this->assertIsInt($position, 'The issuer state of a pushed request is not checked.');
        $this->assertGreaterThan(array_search(StateRule::class, $checkedRules, true), $position);
        $this->assertGreaterThan(array_search(ClientRedirectUriRule::class, $checkedRules, true), $position);

        $offered = array_search(OfferedCredentialsRule::class, $checkedRules, true);
        $scope = array_search(ScopeRule::class, $checkedRules, true);
        $authorizationDetails = array_search(AuthorizationDetailsRule::class, $checkedRules, true);
        $this->assertIsInt($offered, 'What the offer of a pushed request offered is not checked.');
        $this->assertIsInt($scope, 'The scopes of a pushed request are not checked.');
        $this->assertIsInt($authorizationDetails, 'The authorization details of a pushed request are not checked.');
        $this->assertGreaterThan($position, $offered);
        $this->assertGreaterThan($scope, $offered);
        $this->assertGreaterThan($authorizationDetails, $offered);
    }


    /**
     * The rules validate a Request Object together with the form body, its claims superseding form parameters of
     * the same name (RequestParamsResolver), so that is what is persisted, without the client authentication
     * parameters and the Request Object itself: a pushed request is redeemed with its persisted parameters only.
     */
    public function testPersistsTheFormBodyWithTheRequestObjectClaimsSupersedingItWhenJarIsUsed(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $params = [
            'request' => 'token',
            'client_secret' => 'verysecret',
            'some_stray_param' => 'value',
            'scope' => 'profile',
            'state' => 'xyz',
        ];
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);

        $requestObjectPayload = [
            'client_id' => 'client123',
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
            'scope' => 'openid',
        ];
        $requestObjectResult = new Result(RequestObjectRule::class, $requestObjectPayload);
        $this->resultBagMock->method('get')->with(RequestObjectRule::class)->willReturn($requestObjectResult);
        $this->resultBagMock->method('getOrFail')->with(RequestObjectRule::class)->willReturn($requestObjectResult);

        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->with(
                'client123',
                $this->identicalTo([
                    'some_stray_param' => 'value',
                    'scope' => 'openid',
                    'state' => 'xyz',
                    'client_id' => 'client123',
                    'redirect_uri' => 'https://localhost/callback',
                    'response_type' => 'code',
                ]),
            )
            ->willReturn($this->parEntityMock);

        $this->pushedAuthorizationRequestRepositoryMock->expects($this->once())->method('persist');

        $this->sut()->__invoke($this->serverRequestMock);
    }


    /**
     * A Request Object which leaves the scope to the form body was validated with the scope from there, so that
     * scope is persisted with it: a request validated as an OpenID Connect one is redeemed as one, and not as a
     * plain OAuth 2.0 request.
     */
    public function testPersistsTheFormBodyScopeWithARequestObjectWhichLeavesItOut(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();
        $this->serverRequestMock->method('getParsedBody')
            ->willReturn(['request' => 'token', 'scope' => 'openid profile']);

        $requestObjectPayload = [
            'client_id' => 'client123',
            'redirect_uri' => 'https://localhost/callback',
            'response_type' => 'code',
        ];
        $requestObjectResult = new Result(RequestObjectRule::class, $requestObjectPayload);
        $this->resultBagMock->method('get')->with(RequestObjectRule::class)->willReturn($requestObjectResult);
        $this->resultBagMock->method('getOrFail')->with(RequestObjectRule::class)->willReturn($requestObjectResult);

        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())
            ->method('fromData')
            ->with('client123', $this->identicalTo(['scope' => 'openid profile', ...$requestObjectPayload]))
            ->willReturn($this->parEntityMock);

        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testRejectsRequestObjectClientIdClaimWhichDoesNotMatchAuthenticatedClient(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->prepareAuthenticatedClient();

        $this->serverRequestMock->method('getParsedBody')->willReturn(['request' => 'token']);

        $requestObjectResult = new Result(RequestObjectRule::class, ['client_id' => 'otherClient']);
        $this->resultBagMock->method('get')->with(RequestObjectRule::class)->willReturn($requestObjectResult);
        $this->resultBagMock->method('getOrFail')->with(RequestObjectRule::class)->willReturn($requestObjectResult);

        $this->expectException(OidcServerException::class);
        $this->sut()->__invoke($this->serverRequestMock);
    }


    public function testParReturnsJsonErrorResponseForOAuthServerException(): void
    {
        $requestMock = $this->createMock(Request::class);
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);

        // Make __invoke throw an OidcServerException (client authentication failure).
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')->willReturn(null);

        $jsonResponse = new JsonResponse();
        $this->errorResponderMock->expects($this->once())
            ->method('forExceptionJson')
            ->with($this->isInstanceOf(OAuthServerException::class))
            ->willReturn($jsonResponse);

        $this->assertSame($jsonResponse, $this->sut()->par($requestMock));
    }


    public function testParReturnsGenericJsonErrorResponseForUnexpectedThrowable(): void
    {
        $requestMock = $this->createMock(Request::class);
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->method('createRequest')->willReturn($this->serverRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);

        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->authenticatedOAuth2ClientResolverMock->method('forAnySupportedMethod')
            ->willThrowException(new RuntimeException('some internal error'));

        $jsonResponse = new JsonResponse();
        $this->errorResponderMock->expects($this->once())
            ->method('forExceptionJson')
            ->with($this->callback(
                // Internal error details must not leak to the client.
                fn(OAuthServerException $exception): bool =>
                    !str_contains($exception->getMessage(), 'some internal error') &&
                    !str_contains((string)$exception->getHint(), 'some internal error'),
            ))
            ->willReturn($jsonResponse);

        $this->assertSame($jsonResponse, $this->sut()->par($requestMock));
    }


    /**
     * A plain pushed request, authenticated, whose rules let the `dpop_jkt` given here through.
     *
     * @param array<string, string> $params
     */
    protected function preparePushedRequest(array $params, ?string $dpopJkt): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->serverRequestMock->method('getParsedBody')->willReturn($params);
        $this->prepareAuthenticatedClient();
        $this->resultBagMock->method('getOrFail')->willReturnCallback(
            fn(string $key): Result => match ($key) {
                DpopJktRule::class => new Result(DpopJktRule::class, $dpopJkt),
                // The scopes ScopeRule found: the ones the request names, none without a scope parameter.
                ScopeRule::class => new Result(
                    ScopeRule::class,
                    array_map(
                        static fn(string $scope): ScopeEntity => new ScopeEntity($scope),
                        array_filter(explode(' ', $params['scope'] ?? '')),
                    ),
                ),
            },
        );
    }


    protected function verifiedProofBy(string $jwkThumbprint): VerifiedDpopProof
    {
        return new VerifiedDpopProof($this->createStub(DpopProof::class), $jwkThumbprint);
    }


    /**
     * A DPoP proof on a pushed request is checked as at the token endpoint (RFC 9449 section 10.1), against the PAR
     * endpoint URL this OP publishes, with no access token. Its key binds the code: the request is persisted with
     * the key's thumbprint as `dpop_jkt`, and the authorization endpoint takes it as if the client had sent it.
     */
    public function testBindsTheCodeToTheKeyOfTheProofThePushedRequestCarries(): void
    {
        $this->preparePushedRequest(['response_type' => 'code', 'scope' => 'openid'], null);
        $this->dpopProofVerifierMock->expects($this->once())->method('verify')
            ->with($this->serverRequestMock, 'https://op.example.org/oidc/par', null)
            ->willReturn($this->verifiedProofBy('proof-key-jkt'));
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())->method('fromData')
            ->with(
                'client123',
                [
                    'response_type' => 'code',
                    'scope' => 'openid',
                    'client_id' => 'client123',
                    'dpop_jkt' => 'proof-key-jkt',
                ],
            )
            ->willReturn($this->parEntityMock);

        $this->sut()->__invoke($this->serverRequestMock);
    }


    /**
     * A request may send both: `dpop_jkt` and a proof by the key it names.
     */
    public function testAcceptsADpopJktWhichNamesTheKeyOfTheProof(): void
    {
        $this->preparePushedRequest(['response_type' => 'code', 'dpop_jkt' => 'proof-key-jkt'], 'proof-key-jkt');
        $this->dpopProofVerifierMock->method('verify')->willReturn($this->verifiedProofBy('proof-key-jkt'));
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())->method('fromData')
            ->with(
                'client123',
                ['response_type' => 'code', 'dpop_jkt' => 'proof-key-jkt', 'client_id' => 'client123', 'scope' => ''],
            )
            ->willReturn($this->parEntityMock);

        $this->sut()->__invoke($this->serverRequestMock);
    }


    /**
     * A request whose `dpop_jkt` names another key than its proof contradicts itself, and is refused as
     * `invalid_request` (RFC 9449 section 10.1: "MUST reject"); nothing is persisted.
     */
    public function testRefusesADpopJktWhichNamesAnotherKeyThanTheProof(): void
    {
        $this->preparePushedRequest(['response_type' => 'code', 'dpop_jkt' => 'other-key-jkt'], 'other-key-jkt');
        $this->dpopProofVerifierMock->method('verify')->willReturn($this->verifiedProofBy('proof-key-jkt'));
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->never())->method('fromData');
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('persist');

        try {
            $this->sut()->__invoke($this->serverRequestMock);
            $this->fail('The request must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
        }
    }


    /**
     * Without a proof, a `dpop_jkt` the request sends is persisted as sent, and binds the code as at the
     * authorization endpoint; nothing is added to a request which sends neither.
     */
    public function testPersistsADpopJktSentWithoutAProofAsItIs(): void
    {
        $this->preparePushedRequest(['response_type' => 'code', 'dpop_jkt' => 'a-key-jkt'], 'a-key-jkt');
        $this->dpopProofVerifierMock->method('verify')->willReturn(null);
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())->method('fromData')
            ->with(
                'client123',
                ['response_type' => 'code', 'dpop_jkt' => 'a-key-jkt', 'client_id' => 'client123', 'scope' => ''],
            )
            ->willReturn($this->parEntityMock);

        $this->sut()->__invoke($this->serverRequestMock);
    }


    /**
     * The scope decides whether a request is an OpenID Connect one. A request pushed without one, a plain OAuth 2.0
     * or an OpenID4VCI request, is persisted with the empty one it was validated with, rather than none, which
     * would leave its scope to the default scope of the grant at the authorization endpoint.
     */
    public function testPersistsARequestPushedWithoutAScopeWithAnEmptyOne(): void
    {
        $this->preparePushedRequest(['response_type' => 'code', 'state' => 'xyz'], null);
        $this->dpopProofVerifierMock->method('verify')->willReturn(null);
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->once())->method('fromData')
            ->with(
                'client123',
                $this->identicalTo(
                    ['response_type' => 'code', 'state' => 'xyz', 'client_id' => 'client123', 'scope' => ''],
                ),
            )
            ->willReturn($this->parEntityMock);

        $this->sut()->__invoke($this->serverRequestMock);
    }


    /**
     * A pushed request is redeemed with its persisted parameters only (RequestParamsResolver), so one without a
     * response_type, which nothing could supply later, is refused at the push.
     */
    public function testRefusesAPushedRequestWithoutAResponseType(): void
    {
        $this->preparePushedRequest(['scope' => 'openid', 'state' => 'xyz'], null);
        $this->dpopProofVerifierMock->method('verify')->willReturn(null);
        $this->pushedAuthorizationRequestEntityFactoryMock->expects($this->never())->method('fromData');
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('persist');
        $this->loggerMock->expects($this->once())->method('notice')
            ->with('Pushed authorization request rejected: `response_type` parameter not provided.');

        try {
            $this->sut()->__invoke($this->serverRequestMock);
            $this->fail('The request must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
            $this->assertSame('Missing response_type', $exception->getHint());
        }
    }


    /**
     * A proof which fails a check refuses the pushed request as `invalid_dpop_proof`, before any rule runs and
     * with nothing persisted.
     */
    public function testRefusesAPushedRequestWhoseProofFailsACheck(): void
    {
        $refusal = OidcServerException::invalidDpopProof('The DPoP proof has been used before.');
        $this->preparePushedRequest(['response_type' => 'code'], null);
        $this->dpopProofVerifierMock->method('verify')->willThrowException($refusal);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->expects($this->never())->method('check');
        $this->pushedAuthorizationRequestRepositoryMock->expects($this->never())->method('persist');

        try {
            $this->sut()->__invoke($this->serverRequestMock);
            $this->fail('The request must be refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame($refusal, $exception);
        }
    }


    /**
     * `dpop_jkt` is checked among the pushed request's rules, after the ones whose results its refusal reads (the
     * client, the redirect URI, the state).
     */
    public function testChecksTheDpopJktAfterTheRulesItReadsFrom(): void
    {
        $this->serverRequestMock->method('getMethod')->willReturn('POST');
        $this->serverRequestMock->method('getParsedBody')->willReturn(['response_type' => 'code']);
        $this->prepareAuthenticatedClient();
        $this->pushedAuthorizationRequestEntityFactoryMock->method('fromData')->willReturn($this->parEntityMock);
        // The scopes ScopeRule found for a request without a scope parameter: none.
        $this->resultBagMock->method('getOrFail')->willReturn(new Result(ScopeRule::class, []));

        $checkedRules = null;
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->expects($this->once())->method('check')->willReturnCallback(
            function (ServerRequestInterface $request, array $rules) use (&$checkedRules): ResultBag {
                $checkedRules = $rules;

                return $this->resultBagMock;
            },
        );

        $this->sut()->__invoke($this->serverRequestMock);

        $this->assertIsArray($checkedRules);
        $position = array_search(DpopJktRule::class, $checkedRules, true);
        $this->assertIsInt($position, 'The dpop_jkt of a pushed request is not checked.');
        $this->assertGreaterThan(array_search(StateRule::class, $checkedRules, true), $position);
        $this->assertGreaterThan(array_search(ClientRedirectUriRule::class, $checkedRules, true), $position);
    }
}
