<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\Interfaces\AuthorizationValidatableWithRequestRules;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Core\IdToken;

#[CoversClass(AuthorizationServer::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthorizationServerTest extends TestCase
{
    protected const string REDIRECT_URI = 'https://rp.example.org/callback';

    protected const string STATE = 'state-1';

    protected const string POST_LOGOUT_REDIRECT_URI = 'https://rp.example.org/logged-out';

    protected const string UI_LOCALES = 'hr en';


    protected MockObject $clientRepositoryMock;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $scopeRepositoryMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $resultBagMock;

    protected MockObject $requestMock;

    protected CryptKey $privateKey;

    /** @var array<string,mixed> Results the rules are taken to have produced, keyed by rule class. */
    protected array $results = [];

    /** Thrown by the rules manager instead of returning a result bag. */
    protected ?OidcServerException $ruleException = null;

    /** @var array{0: array<string>, 1: array<\SimpleSAML\OpenID\Codebooks\HttpMethodsEnum>}|null */
    protected ?array $checkedWith = null;


    protected function setUp(): void
    {
        $this->clientRepositoryMock = $this->createMock(ClientRepositoryInterface::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepositoryInterface::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestMock = $this->createMock(ServerRequestInterface::class);
        $this->ruleException = null;
        $this->checkedWith = null;

        // A real key, since the parent turns anything else into one and validates it on the way.
        $this->privateKey = new CryptKey(dirname(__DIR__, 3) . '/cert/oidc_module.key', null, false);

        $this->results = [
            StateRule::class => self::STATE,
            ClientRedirectUriRule::class => self::REDIRECT_URI,
            ResponseModeRule::class => new QueryResponseMode(),
            IdTokenHintRule::class => $this->createMock(IdToken::class),
            PostLogoutRedirectUriRule::class => self::POST_LOGOUT_REDIRECT_URI,
            UiLocalesRule::class => self::UI_LOCALES,
        ];

        $this->resultBagMock = $this->createMock(ResultBagInterface::class);
        $this->resultBagMock->method('getOrFail')->willReturnCallback(
            fn(string $key): Result => new Result($key, $this->results[$key] ?? null),
        );

        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestRulesManagerMock->method('check')->willReturnCallback(
            function (
                ServerRequestInterface $request,
                array $ruleKeysToExecute,
                mixed $responseMode = null,
                array $allowedServerRequestMethods = [],
            ): ResultBagInterface {
                $this->checkedWith = [$ruleKeysToExecute, $allowedServerRequestMethods];

                if ($this->ruleException !== null) {
                    throw $this->ruleException;
                }

                return $this->resultBagMock;
            },
        );
    }


    protected function sut(?RequestRulesManager $requestRulesManager = null): AuthorizationServer
    {
        return new AuthorizationServer(
            $this->clientRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->scopeRepositoryMock,
            $this->privateKey,
            'encryption-key',
            null,
            $requestRulesManager ?? $this->requestRulesManagerMock,
            $this->loggerServiceMock,
        );
    }


    /**
     * A grant type which says it can respond to the request, and which can be validated against rules
     * this server has already checked.
     */
    protected function validatableGrantType(
        string $identifier,
        bool $canRespond = true,
        ?AuthorizationRequest $authorizationRequest = null,
    ): GrantTypeInterface {
        $grantTypeMock = $this->createMockForIntersectionOfInterfaces([
            GrantTypeInterface::class,
            AuthorizationValidatableWithRequestRules::class,
        ]);
        $grantTypeMock->method('getIdentifier')->willReturn($identifier);
        $grantTypeMock->method('canRespondToAuthorizationRequest')->willReturn($canRespond);
        $grantTypeMock->method('validateAuthorizationRequestWithRequestRules')
            ->willReturn($authorizationRequest ?? new AuthorizationRequest());

        /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantTypeMock */
        return $grantTypeMock;
    }


    /**
     * Validation happens against rules this server checks itself, so a grant type which cannot take that
     * result bag has nothing to validate against.
     */
    protected function plainGrantType(string $identifier, bool $canRespond = true): GrantTypeInterface
    {
        $grantTypeMock = $this->createMock(GrantTypeInterface::class);
        $grantTypeMock->method('getIdentifier')->willReturn($identifier);
        $grantTypeMock->method('canRespondToAuthorizationRequest')->willReturn($canRespond);

        return $grantTypeMock;
    }


    /**
     * The rules are what validates a request, so a server built without them could only ever accept
     * whatever it was sent. Refused at construction rather than at the first request.
     */
    public function testCanNotBeBuiltWithoutARequestRulesManager(): void
    {
        $this->expectException(LogicException::class);

        new AuthorizationServer(
            $this->clientRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->scopeRepositoryMock,
            $this->privateKey,
            'encryption-key',
            null,
            null,
            $this->loggerServiceMock,
        );
    }


    /**
     * The rule list is the validation: a rule dropped from it is a check silently not performed, and
     * `state` and the redirect URI are needed even to refuse the request properly.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testChecksTheRulesAnAuthorizationRequestNeeds(): void
    {
        $sut = $this->sut();
        $sut->enableGrantType($this->validatableGrantType('authorization_code'));

        $sut->validateAuthorizationRequest($this->requestMock);

        $this->assertSame(
            [
                StateRule::class,
                ClientRule::class,
                RequestUriRule::class,
                ClientRedirectUriRule::class,
                ResponseModeRule::class,
            ],
            $this->checkedWith[0] ?? null,
        );
        // Both, since an authorization request may arrive either way.
        $this->assertSame([HttpMethodsEnum::GET, HttpMethodsEnum::POST], $this->checkedWith[1] ?? null);
    }


    /**
     * A request which fails a rule has not established a redirect URI worth trusting, so the refusal
     * goes back to the user agent rather than to the client - and it says which check failed.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testTurnsAFailedRuleIntoABadRequest(): void
    {
        $this->ruleException = OidcServerException::invalidRequest('client_id', 'Client ID was not provided');

        $this->expectException(BadRequest::class);
        $this->expectExceptionMessageMatches('/Client ID was not provided/');

        $this->sut()->validateAuthorizationRequest($this->requestMock);
    }


    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testRefusesAnAuthorizationRequestNoGrantTypeCanRespondTo(): void
    {
        $sut = $this->sut();
        $sut->enableGrantType($this->plainGrantType('implicit', canRespond: false));

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('The response type is not supported by the authorization server.');

        $sut->validateAuthorizationRequest($this->requestMock);
    }


    /**
     * With no grant type enabled at all there is likewise nothing which can respond, and the answer is
     * the same one: the response type this request asked for is not supported here.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testRefusesAnAuthorizationRequestWhenNoGrantTypeIsEnabled(): void
    {
        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorizationRequest($this->requestMock);
    }


    /**
     * This server checks the rules once and hands the results on, so a grant type which cannot be
     * validated against them would have to validate the request a second time, by its own rules. That is
     * a server error rather than a bad request: the request may be perfectly good.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testRefusesAGrantTypeWhichCanNotBeValidatedWithTheCheckedRules(): void
    {
        $sut = $this->sut();
        $sut->enableGrantType($this->plainGrantType('authorization_code'));

        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessageMatches('/validatable with already validated result bag/');

        $sut->validateAuthorizationRequest($this->requestMock);
    }


    /**
     * The first grant type which can respond gets the request, together with the results this server has
     * already established - which is what stops the same parameters being validated twice, by two sets of
     * rules which can disagree.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testHandsTheRequestAndTheCheckedRulesToTheGrantTypeWhichCanRespond(): void
    {
        $authorizationRequest = new AuthorizationRequest();

        $grantTypeMock = $this->createMockForIntersectionOfInterfaces([
            GrantTypeInterface::class,
            AuthorizationValidatableWithRequestRules::class,
        ]);
        $grantTypeMock->method('getIdentifier')->willReturn('authorization_code');
        $grantTypeMock->method('canRespondToAuthorizationRequest')->willReturn(true);
        $grantTypeMock->expects($this->once())
            ->method('validateAuthorizationRequestWithRequestRules')
            ->with($this->requestMock, $this->resultBagMock)
            ->willReturn($authorizationRequest);

        $sut = $this->sut();
        /** @var \League\OAuth2\Server\Grant\GrantTypeInterface $grantTypeMock */
        $sut->enableGrantType($grantTypeMock);

        $this->assertSame($authorizationRequest, $sut->validateAuthorizationRequest($this->requestMock));
    }


    /**
     * A grant type which cannot respond is passed over rather than taken as the answer, so the one which
     * can still gets the request.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Throwable
     */
    public function testPassesOverAGrantTypeWhichCanNotRespond(): void
    {
        $authorizationRequest = new AuthorizationRequest();

        $sut = $this->sut();
        $sut->enableGrantType($this->plainGrantType('implicit', canRespond: false));
        $sut->enableGrantType($this->validatableGrantType(
            'authorization_code',
            authorizationRequest: $authorizationRequest,
        ));

        $this->assertSame($authorizationRequest, $sut->validateAuthorizationRequest($this->requestMock));
    }


    /**
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \Throwable
     */
    public function testChecksTheRulesALogoutRequestNeeds(): void
    {
        $this->sut()->validateLogoutRequest($this->requestMock);

        $this->assertSame(
            [
                StateRule::class,
                IdTokenHintRule::class,
                PostLogoutRedirectUriRule::class,
                UiLocalesRule::class,
            ],
            $this->checkedWith[0] ?? null,
        );
        $this->assertSame([HttpMethodsEnum::GET, HttpMethodsEnum::POST], $this->checkedWith[1] ?? null);
    }


    /**
     * @throws \Throwable
     */
    public function testTurnsAFailedLogoutRuleIntoABadRequest(): void
    {
        $this->ruleException = OidcServerException::invalidRequest(
            'post_logout_redirect_uri',
            'Post logout redirect URI is not registered',
        );

        $this->expectException(BadRequest::class);
        $this->expectExceptionMessageMatches('/Post logout redirect URI is not registered/');

        $this->sut()->validateLogoutRequest($this->requestMock);
    }


    /**
     * The logout request is assembled from what the rules established, and each value has to come from
     * its own rule: swapping two of them would send the user agent somewhere the client never registered.
     *
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \Throwable
     */
    public function testBuildsALogoutRequestFromWhatTheRulesEstablished(): void
    {
        $logoutRequest = $this->sut()->validateLogoutRequest($this->requestMock);

        $this->assertSame($this->results[IdTokenHintRule::class], $logoutRequest->getIdTokenHint());
        $this->assertSame(self::POST_LOGOUT_REDIRECT_URI, $logoutRequest->getPostLogoutRedirectUri());
        $this->assertSame(self::STATE, $logoutRequest->getState());
        $this->assertSame(self::UI_LOCALES, $logoutRequest->getUiLocales());
    }
}
