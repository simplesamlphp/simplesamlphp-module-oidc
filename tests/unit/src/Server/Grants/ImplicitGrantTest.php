<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use DateInterval;
use DateTimeImmutable;
use Exception;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LogicException;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\EntityStringRepresentationInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AcrValuesRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AddClaimsToIdTokenRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\LoginHintRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\MaxAgeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\PromptRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestedClaimsRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequestObjectRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredNonceRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseTypeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\UiLocalesRule;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\OpenID\Core\IdTokenHint;

/**
 * The implicit flow: what the OP validates on an authorization request, and what it puts in the fragment.
 *
 * Two properties of this grant are load-bearing and invisible in a coverage number, and the fixtures below
 * are shaped around them.
 *
 * The first is that validateAuthorizationRequestWithRequestRules() copies eleven values out of eleven rule
 * results into eleven setters, in eleven lines of the same shape. Every fixture here is therefore a distinct
 * sentinel: with values shared between them, most of those transfers could be wired to each other's rules
 * and no assertion would notice.
 *
 * The second is that the response mode is resolved twice -- once from the incoming result bag, to tell the
 * rules which mode the request will be answered in, and again from the bag check() hands back, which is the
 * one the authorization request ends up carrying. Neither read is of a rule this method runs: ResponseModeRule
 * is not in its list, and the value is in both bags only because the caller resolved it beforehand. In
 * production the two bags are the same object, since the manager is handed the incoming one to fill and
 * returns it, so the two bags here deliberately hold different modes.
 *
 * Two guards in completeOidcAuthorizationRequest() reject an issued access token that has no string
 * representation, or that is not the module's own AccessTokenEntity. Neither can fire in production: the
 * token comes from AccessTokenEntityFactory::fromData(), whose declared return type is AccessTokenEntity,
 * which satisfies both, and return type covariance stops a subclass from widening that. The first is
 * reachable from a test all the same, because issueAccessToken() is declared to return the wider
 * AccessTokenEntityInterface, and it is covered below by stubbing that one method on the grant.
 *
 * The second guard is this file's only uncovered statements, and it is unreachable rather than skipped.
 * Failing it while passing the first needs a class which implements both AccessTokenEntityInterface and
 * EntityStringRepresentationInterface without extending AccessTokenEntity, and the module has no such
 * class -- AccessTokenEntity is the only implementor of that interface in it. Nor can PHPUnit synthesise
 * one: League's AccessTokenEntityInterface already declares toString(), the single method
 * EntityStringRepresentationInterface exists to require, so the two cannot be mocked as an intersection.
 */
#[CoversClass(ImplicitGrant::class)]
#[UsesClass(AuthorizationRequest::class)]
#[UsesClass(FragmentResponseMode::class)]
#[UsesClass(OidcServerException::class)]
#[UsesClass(QueryResponseMode::class)]
#[UsesClass(Result::class)]
#[UsesClass(ResultBag::class)]
#[UsesClass(ScopeEntity::class)]
#[UsesClass(UserEntity::class)]
#[AllowMockObjectsWithoutExpectations]
class ImplicitGrantTest extends TestCase
{
    private const string CLIENT_ID = 'client-id';

    private const string USER_ID = 'user-id';

    /** The redirect URI carried by the authorization request itself. */
    private const string REDIRECT_URI = 'https://rp.example.org/implicit-callback';

    /** A different URI, the one the client registered. The request's own has to win over it. */
    private const string REGISTERED_REDIRECT_URI = 'https://rp.example.org/registered-callback';

    private const string STATE = 'state-from-the-state-rule';

    private const string NONCE = 'nonce-from-the-nonce-rule';

    private const string DEFAULT_SCOPE = 'default-scope-of-the-grant';

    private const int AUTH_TIME = 1234567890;


    protected MockObject $idTokenBuilderMock;

    protected DateInterval $accessTokenTtl1h;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $accessTokenEntityFactoryMock;

    protected MockObject $scopeRepositoryMock;

    protected MockObject $serverRequestMock;

    protected MockObject $loggerServiceMock;

    /** Response mode in the incoming bag, which is the one the rule check is told to run under. */
    private ResponseModeInterface $incomingResponseMode;

    /** Response mode in the bag check() hands back, which is the one that lands on the request. */
    private ResponseModeInterface $checkedResponseMode;

    private ResultBag $incomingResultBag;

    /** @var array<int,mixed> Arguments RequestRulesManager::check() was called with. */
    private array $checkArguments = [];

    /** @var array<string,string> Data published to the manager so far. */
    private array $publishedData = [];

    /** @var array<string,string> Data published by the time check() ran; anything later is not in here. */
    private array $dataAtCheckTime = [];

    private ?ResultBagInterface $predefinedResultBag = null;

    /** The bag predefined by the time check() ran, which is the only moment at which it is of any use. */
    private ?ResultBagInterface $predefinedAtCheckTime = null;

    /** @var array<int,mixed> Arguments IdTokenBuilder::buildFor() was called with. */
    private array $idTokenArguments = [];

    /** @var array<int,mixed> Arguments AccessTokenEntityFactory::fromData() was called with. */
    private array $accessTokenArguments = [];

    /** @var array<int,mixed> Arguments ScopeRepositoryInterface::finalizeScopes() was called with. */
    private array $finalizeScopesArguments = [];


    protected function setUp(): void
    {
        $this->idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $this->accessTokenTtl1h = new DateInterval('PT1H');
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->incomingResponseMode = new QueryResponseMode();
        $this->checkedResponseMode = new FragmentResponseMode();
    }


    protected function sut(
        ?IdTokenBuilder $idTokenBuilder = null,
        ?DateInterval $accessTokenTtl = null,
        ?AccessTokenRepositoryInterface $accessTokenRepository = null,
        ?RequestRulesManager $requestRulesManager = null,
        ?RequestParamsResolver $requestParamsResolver = null,
        ?AccessTokenEntityFactory $accessTokenEntityFactory = null,
        ?ScopeRepositoryInterface $scopeRepository = null,
        ?LoggerService $loggerService = null,
    ): ImplicitGrant {
        $idTokenBuilder ??= $this->idTokenBuilderMock;
        $accessTokenTtl ??= $this->accessTokenTtl1h;
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $requestRulesManager ??= $this->requestRulesManagerMock;
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $accessTokenEntityFactory ??= $this->accessTokenEntityFactoryMock;
        $scopeRepository ??= $this->scopeRepositoryMock;
        $loggerService ??= $this->loggerServiceMock;


        $implicitGrant = new ImplicitGrant(
            $idTokenBuilder,
            $accessTokenTtl,
            $accessTokenRepository,
            $requestRulesManager,
            $requestParamsResolver,
            $accessTokenEntityFactory,
            $loggerService,
        );

        $implicitGrant->setScopeRepository($scopeRepository);
        // AuthorizationServer::enableGrantType() does this in production. Without it the default scope is an
        // uninitialized typed property, and reading it to publish it to the rules is a fatal error.
        $implicitGrant->setDefaultScope(self::DEFAULT_SCOPE);

        return $implicitGrant;
    }


    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(ImplicitGrant::class, $this->sut());
    }


    public function testCanRespondToAuthorizationRequestForIdTokenTokenResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'id_token token']);

        $this->assertTrue($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    public function testCanRespondToAuthorizationRequestForIdTokenResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'id_token']);

        $this->assertTrue($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    public function testCanRespondToAuthorizationRequestReturnsFalseIfNoClientId(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['response_type' => 'id_token']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    /**
     * A response type naming both `code` and `id_token` is the hybrid flow, which this grant declines so the
     * authorization code grant can take it. The client_id matters: without it the method returns false at the
     * guard clause above, and the test would pass with the hybrid check deleted from the grant entirely.
     */
    public function testCanRespondToAuthorizationRequestReturnsFalseForHybridFlow(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'code id_token']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    public function testCanRespondToAuthorizationRequestReturnsFalseForTheAuthorizationCodeFlow(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'code']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    public function testCanRespondToAuthorizationRequestReturnsFalseWithoutAResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    /**
     * A repeated response_type parameter arrives as an array, which the explode() below would not survive.
     */
    public function testCanRespondToAuthorizationRequestReturnsFalseForANonStringResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => ['id_token']]);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    /**
     * The authorization request may arrive by GET or POST and by nothing else, and the grant says so when it
     * asks for the parameters. That is what keeps a parameter smuggled in by another method out of the
     * decision about which grant handles the request.
     */
    public function testAuthorizationRequestParametersAreReadFromGetAndPostOnly(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->with($this->serverRequestMock, [HttpMethodsEnum::GET, HttpMethodsEnum::POST])
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'id_token']);

        $this->assertTrue($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }


    public function testCompleteAuthorizationRequestThrowsForNonOidcRequests(): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('unexpected authorization request type'),
                $this->arrayHasKey('type'),
            );

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Unexpected');

        $this->sut()->completeAuthorizationRequest($this->createMock(
            \League\OAuth2\Server\RequestTypes\AuthorizationRequest::class,
        ));
    }


    public function testCanCompleteAuthorizationRequest(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->sut()->completeAuthorizationRequest($this->authorizationRequest()),
        );
    }


    /**
     * The grant forwards the "add claims to ID Token" decision (made by AddClaimsToIdTokenRule and carried on
     * the authorization request) to the ID Token builder. When it is true, the user's claims are released in
     * the ID Token.
     */
    #[DataProvider('addClaimsToIdTokenProvider')]
    public function testForwardsTheClaimsReleaseDecisionToTheIdTokenBuilder(bool $addClaimsToIdToken): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $authorizationRequest = $this->authorizationRequest();
        $authorizationRequest->setAddClaimsToIdToken($addClaimsToIdToken);

        $this->completed($authorizationRequest);

        $this->assertSame($addClaimsToIdToken, $this->idTokenArguments[2]);
    }


    /**
     * @return array<string,array{0:bool}>
     */
    public static function addClaimsToIdTokenProvider(): array
    {
        return [
            'the claims are released in the ID Token' => [true],
            // When the decision is false the claims stay out of the ID Token, and a client which wants them
            // has to fetch them from the UserInfo endpoint with the access token.
            'the claims are left out of the ID Token' => [false],
        ];
    }


    /**
     * Every value the method transfers is asserted here, each from its own fixture. The transfers are eleven
     * lines of the same shape -- read a rule result, call a setter -- so shared fixtures would let any two of
     * them be crossed without an assertion noticing. The response mode is the one transfer left out of this
     * test: it only says anything when the two bags differ, so it has the test below to itself.
     */
    public function testEveryRuleResultIsCarriedOntoTheAuthorizationRequest(): void
    {
        $client = $this->clientMock();

        $authorizationRequest = $this->validatedAuthorizationRequest(client: $client);

        $this->assertSame($client, $authorizationRequest->getClient());
        $this->assertSame(self::REDIRECT_URI, $authorizationRequest->getRedirectUri());
        $this->assertSame('implicit', $authorizationRequest->getGrantTypeId());
        $this->assertSame(self::STATE, $authorizationRequest->getState());
        $this->assertSame(self::NONCE, $authorizationRequest->getNonce());
        $this->assertSame(self::AUTH_TIME, $authorizationRequest->getAuthTime());
        $this->assertSame(['userinfo' => ['email' => null]], $authorizationRequest->getClaims());
        $this->assertTrue($authorizationRequest->getAddClaimsToIdToken());
        $this->assertSame('id_token token', $authorizationRequest->getResponseType());
        $this->assertSame(['urn:acr:from-the-acr-rule'], $authorizationRequest->getRequestedAcrValues());
        $this->assertSame('en-GB', $authorizationRequest->getUiLocales());
        $this->assertSame('login-hint-from-the-rule', $authorizationRequest->getLoginHint());
        $this->assertSame('subject-from-the-id-token-hint', $authorizationRequest->getIdTokenHintSubject());

        $scopes = $authorizationRequest->getScopes();
        $this->assertCount(2, $scopes);
        $this->assertSame('openid', $scopes[0]->getIdentifier());
        $this->assertSame('profile', $scopes[1]->getIdentifier());
    }


    /**
     * The response mode is read from both bags: the incoming one decides the mode the rules run under, and
     * the one check() hands back is what the authorization request carries. In production they are the same
     * object, so only two different modes can show that neither read has been wired to the other bag.
     */
    public function testTheRulesRunUnderTheIncomingResponseModeAndTheRequestCarriesTheCheckedOne(): void
    {
        $authorizationRequest = $this->validatedAuthorizationRequest();

        $this->assertSame($this->incomingResponseMode, $this->checkArguments[2]);
        $this->assertSame($this->checkedResponseMode, $authorizationRequest->getResponseMode());
    }


    /**
     * Two of these orderings are load-bearing and documented only in comments beside the list: LoginHintRule
     * must precede PromptRule and MaxAgeRule, which consume its result when they trigger re-authentication,
     * and IdTokenHintRule must precede PromptRule, which consumes its result to keep a prompt=none request
     * tied to the End-User the hint identifies. Asserting the list in order pins those two with the rest.
     */
    public function testTheRequestRulesRunInTheOrderTheirDependenciesRequire(): void
    {
        $this->validatedAuthorizationRequest();

        $this->assertSame(
            [
                ScopeRule::class,
                RequestObjectRule::class,
                LoginHintRule::class,
                IdTokenHintRule::class,
                PromptRule::class,
                MaxAgeRule::class,
                RequiredOpenIdScopeRule::class,
                ResponseTypeRule::class,
                AddClaimsToIdTokenRule::class,
                RequiredNonceRule::class,
                RequestedClaimsRule::class,
                AcrValuesRule::class,
                UiLocalesRule::class,
            ],
            $this->checkArguments[1],
        );
    }


    public function testTheRequestRulesReadTheRequestAsGetOrPostOnly(): void
    {
        $this->validatedAuthorizationRequest();

        $this->assertSame($this->serverRequestMock, $this->checkArguments[0]);
        $this->assertSame([HttpMethodsEnum::GET, HttpMethodsEnum::POST], $this->checkArguments[3]);
    }


    /**
     * ScopeRule reads both of these off the manager rather than off the grant, so a missing publication would
     * surface as a request without the OP's default scope, or as a scope string that is never split.
     */
    public function testTheDataTheScopeRuleNeedsIsPublishedBeforeTheRulesRun(): void
    {
        $this->validatedAuthorizationRequest();

        $this->assertSame(
            ['default_scope' => self::DEFAULT_SCOPE, 'scope_delimiter_string' => ' '],
            $this->dataAtCheckTime,
        );
    }


    /**
     * The results the caller already resolved are handed to the manager, not merely read here, so that the
     * rules which run next can see the client, the redirect URI and the state they were resolved from.
     */
    public function testTheAlreadyResolvedResultsArePublishedToTheRulesThatRunNext(): void
    {
        $this->validatedAuthorizationRequest();

        $this->assertSame($this->incomingResultBag, $this->predefinedAtCheckTime);
    }


    /**
     * state is optional, and an absent one must stay absent rather than become a literal null in the response.
     */
    public function testAnAbsentStateIsLeftUnsetOnTheAuthorizationRequest(): void
    {
        $this->assertNull($this->validatedAuthorizationRequest(state: null)->getState());
    }


    public function testAnAbsentMaxAgeLeavesTheAuthenticationTimeUnset(): void
    {
        $authorizationRequest = $this->validatedAuthorizationRequest(withoutRules: [MaxAgeRule::class]);

        $this->assertNull($authorizationRequest->getAuthTime());
    }


    /**
     * @param array<class-string,mixed> $ruleResults
     * @param class-string[] $withoutRules
     * @param array<array-key,mixed>|null $expected
     */
    #[DataProvider('requestedClaimsProvider')]
    public function testRequestedClaimsAreCarriedOnlyWhenTheRuleProducedThem(
        array $ruleResults,
        array $withoutRules,
        ?array $expected,
    ): void {
        $authorizationRequest = $this->validatedAuthorizationRequest($ruleResults, $withoutRules);

        $this->assertSame($expected, $authorizationRequest->getClaims());
    }


    /**
     * @return array<string,array{0:array<class-string,mixed>,1:class-string[],2:array<array-key,mixed>|null}>
     */
    public static function requestedClaimsProvider(): array
    {
        return [
            'the rule did not run' => [[], [RequestedClaimsRule::class], null],
            'the rule ran and found nothing' => [[RequestedClaimsRule::class => null], [], null],
            'the rule found a value which is not a claims structure' => [
                [RequestedClaimsRule::class => 'not-a-claims-structure'],
                [],
                null,
            ],
            'the rule produced claims' => [
                [RequestedClaimsRule::class => ['id_token' => ['acr' => null]]],
                [],
                ['id_token' => ['acr' => null]],
            ],
        ];
    }


    public function testAnAbsentIdTokenHintLeavesTheSubjectUnset(): void
    {
        $authorizationRequest = $this->validatedAuthorizationRequest([IdTokenHintRule::class => null]);

        $this->assertNull($authorizationRequest->getIdTokenHintSubject());
    }


    /**
     * A rule which produced no result is a defect in the wiring, not a request the OP can answer, and it is
     * reported as the rule that is missing rather than surfacing later as an unexplained null. Most of these
     * belong to this method's own rule list; ResponseModeRule does not, and is resolved by the caller before
     * the method runs, but it is read back out of the checked bag all the same and fails in the same way.
     *
     * @param class-string $rule
     */
    #[DataProvider('requiredRuleProvider')]
    public function testAMissingRequiredRuleResultNamesTheRuleThatDidNotProduceIt(string $rule): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage($rule);

        $this->validatedAuthorizationRequest(withoutRules: [$rule]);
    }


    /**
     * @return array<string,array{0:class-string}>
     */
    public static function requiredRuleProvider(): array
    {
        return [
            'scope' => [ScopeRule::class],
            'nonce' => [RequiredNonceRule::class],
            'add claims to ID Token' => [AddClaimsToIdTokenRule::class],
            'response type' => [ResponseTypeRule::class],
            'ACR values' => [AcrValuesRule::class],
            'UI locales' => [UiLocalesRule::class],
            'login hint' => [LoginHintRule::class],
            'ID Token hint' => [IdTokenHintRule::class],
            'response mode' => [ResponseModeRule::class],
        ];
    }


    /**
     * The authorization screen attaches the authenticated End-User to the request. Without one there is
     * nobody to issue tokens for, so the grant refuses rather than minting a token bound to nothing.
     */
    public function testCompletingWithoutAnAuthenticatedUserFails(): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('no authenticated user'),
                ['client_id' => self::CLIENT_ID],
            );

        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('UserEntityInterface');

        $this->sut()->completeAuthorizationRequest($this->authorizationRequest(withUser: false));
    }


    /**
     * A denial is the End-User's answer and it belongs back at the client, as the access_denied error at the
     * redirect URI, carrying the state so the client can match it to the request it made.
     *
     * Where the error lands is pinned rather than endorsed. With a response mode negotiated it is delivered
     * in that mode. With none, the grant hands null to accessDenied() and OidcServerException falls back to
     * the query string -- where the success path at the end of the same method falls back to the fragment
     * instead. The disagreement is recorded here rather than fixed, and it is latent either way, since a
     * request which reached this point was given a response mode by getOrFail() during validation.
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null $responseMode
     */
    #[DataProvider('deniedResponseModeProvider')]
    public function testADeniedAuthorizationIsReportedToTheClientAsAccessDenied(
        ?ResponseModeInterface $responseMode,
        string $expectedSeparator,
    ): void {
        $this->loggerServiceMock->expects($this->once())
            ->method('notice')
            ->with($this->stringContains('denied by the user'), ['client_id' => self::CLIENT_ID]);

        try {
            $this->sut()->completeAuthorizationRequest(
                $this->authorizationRequest(responseMode: $responseMode, isApproved: false),
            );
            $this->fail('A denied authorization request should not complete.');
        } catch (OidcServerException $exception) {
            $this->assertSame('access_denied', $exception->getErrorType());
            $this->assertSame(self::REDIRECT_URI, $exception->getRedirectUri());
            $this->assertSame(self::STATE, $exception->getPayload()['state']);

            $location = $exception->generateHttpResponse(new Response())->getHeaderLine('location');
            $this->assertStringStartsWith(self::REDIRECT_URI . $expectedSeparator, $location);
        }
    }


    /**
     * @return array<string,array{0:\SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface|null,1:string}>
     */
    public static function deniedResponseModeProvider(): array
    {
        return [
            'the negotiated fragment mode' => [new FragmentResponseMode(), '#'],
            'the negotiated query mode' => [new QueryResponseMode(), '?'],
            'no negotiated mode at all' => [null, '?'],
        ];
    }


    /**
     * `id_token token` asks for the access token in the authorization response itself, so it rides in the
     * fragment beside the ID Token, with its type and its remaining lifetime.
     */
    public function testTheAccessTokenIsReturnedInTheResponseForTheIdTokenTokenResponseType(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        // Deliberately not the grant's own one hour TTL: expires_in has to be the remaining life of this
        // token, and taking it from the configured lifetime instead would agree with any token that happens
        // to have been issued for the same span.
        $this->accessTokenIsIssued('the-access-token', 900);
        $this->idTokenIsBuilt('the-id-token');

        $params = $this->paramsIn(
            $this->locationOf($this->completed($this->authorizationRequest(responseType: 'id_token token'))),
            PHP_URL_FRAGMENT,
        );

        $this->assertSame('the-access-token', $params['access_token']);
        $this->assertSame('Bearer', $params['token_type']);
        $this->assertEqualsWithDelta(900, (int)$params['expires_in'], 5);
        $this->assertSame('the-id-token', $params['id_token']);
        $this->assertSame(self::STATE, $params['state']);
    }


    /**
     * A plain `id_token` request gets no access token in the response; the ID Token is the whole answer. One
     * is still issued and persisted, because the ID Token is built from it, but it never reaches the client,
     * so nobody can present it at the UserInfo endpoint either.
     */
    public function testTheAccessTokenIsWithheldForThePlainIdTokenResponseType(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $accessToken = $this->accessTokenIsIssued('the-access-token');
        $this->idTokenIsBuilt('the-id-token');

        // The token is still issued and stored, which is what the docblock above rests on.
        $this->accessTokenRepositoryMock->expects($this->once())
            ->method('persistNewAccessToken')
            ->with($accessToken);

        $params = $this->paramsIn(
            $this->locationOf($this->completed($this->authorizationRequest(responseType: 'id_token'))),
            PHP_URL_FRAGMENT,
        );

        $this->assertArrayNotHasKey('access_token', $params);
        $this->assertArrayNotHasKey('token_type', $params);
        $this->assertArrayNotHasKey('expires_in', $params);
        $this->assertSame('the-id-token', $params['id_token']);
        $this->assertSame(self::STATE, $params['state']);
    }


    /**
     * state is optional, and a request without one gets a response without one: http_build_query() drops the
     * null the grant puts in the response parameters unconditionally, so neither redirect mode emits it.
     *
     * That null does survive into form_post, which is also a supported response mode: FormPostResponseMode
     * hands the parameters to formpost.twig, whose loop renders every one of them, so a stateless request
     * answered that way posts back an empty state field. Recorded rather than fixed here.
     */
    public function testAResponseToARequestWithoutStateCarriesNoStateBack(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt('the-id-token');

        $params = $this->paramsIn(
            $this->locationOf($this->completed($this->authorizationRequest(state: null))),
            PHP_URL_FRAGMENT,
        );

        $this->assertArrayNotHasKey('state', $params);
        $this->assertSame('the-id-token', $params['id_token']);
    }


    /**
     * at_hash is what lets the client tie the ID Token to the access token delivered with it, so the ID Token
     * carries it exactly when the access token is in the same response, and never otherwise. Both halves are
     * the same decision, read off the response type.
     */
    #[DataProvider('accessTokenHashProvider')]
    public function testTheIdTokenCarriesTheAccessTokenHashExactlyWhenTheAccessTokenIsReturned(
        string $responseType,
        bool $expected,
    ): void {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $this->completed($this->authorizationRequest(responseType: $responseType));

        $this->assertSame($expected, $this->idTokenArguments[3]);
    }


    /**
     * @return array<string,array{0:string,1:bool}>
     */
    public static function accessTokenHashProvider(): array
    {
        return [
            'the access token is in the response' => ['id_token token', true],
            'the access token is not in the response' => ['id_token', false],
        ];
    }


    /**
     * Eight values reach the ID Token builder positionally: the user, the access token, the two booleans,
     * and then the nonce, the authentication time, the ACR and the session id. Three of those last four are
     * nullable strings, so distinct fixtures are what keep the nonce from arriving as the ACR, or the ACR as
     * the session id.
     */
    public function testTheIdTokenIsBuiltFromTheUserTheAccessTokenAndTheRequestContext(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $accessToken = $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $authorizationRequest = $this->authorizationRequest();
        $authorizationRequest->setAddClaimsToIdToken(true);
        $authorizationRequest->setAuthTime(self::AUTH_TIME);
        $authorizationRequest->setAcr('urn:acr:on-the-request');
        $authorizationRequest->setSessionId('session-id-on-the-request');

        $this->completed($authorizationRequest);

        $this->assertSame(self::USER_ID, $this->idTokenArguments[0]->getIdentifier());
        $this->assertSame($accessToken, $this->idTokenArguments[1]);
        $this->assertTrue($this->idTokenArguments[2]);
        $this->assertFalse($this->idTokenArguments[3]);
        $this->assertSame(self::NONCE, $this->idTokenArguments[4]);
        $this->assertSame(self::AUTH_TIME, $this->idTokenArguments[5]);
        $this->assertSame('urn:acr:on-the-request', $this->idTokenArguments[6]);
        $this->assertSame('session-id-on-the-request', $this->idTokenArguments[7]);
    }


    /**
     * finalizeScopes() is where an OP narrows or extends what the request asked for, so the token has to be
     * issued for what came back from it and not for what went in. The two sets are deliberately disjoint.
     */
    public function testTheAccessTokenIsIssuedForTheFinalizedScopesNotTheRequestedOnes(): void
    {
        $requested = new ScopeEntity('openid');
        $finalized = new ScopeEntity('profile');

        $this->scopesAreFinalizedAs($finalized);
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $authorizationRequest = $this->authorizationRequest();
        $authorizationRequest->setScopes([$requested]);

        $this->completed($authorizationRequest);

        $this->assertSame([$requested], $this->finalizeScopesArguments[0]);
        $this->assertSame('implicit', $this->finalizeScopesArguments[1]);
        $this->assertSame(self::CLIENT_ID, $this->finalizeScopesArguments[2]->getIdentifier());
        $this->assertSame(self::USER_ID, $this->finalizeScopesArguments[3]);

        $this->assertSame([$finalized], $this->accessTokenArguments[2]);
        $this->assertSame(self::USER_ID, $this->accessTokenArguments[4]);
    }


    /**
     * The rest of what the token is built from: the client it belongs to, the claims the request asked for --
     * which is how a request for claims survives as far as the UserInfo endpoint -- and an expiry taken from
     * the grant's own configured access token lifetime rather than from anything on the request.
     */
    public function testTheAccessTokenIsIssuedForTheClientTheRequestedClaimsAndTheConfiguredLifetime(): void
    {
        $client = $this->clientMock();

        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $authorizationRequest = $this->authorizationRequest(client: $client);
        $authorizationRequest->setClaims(['userinfo' => ['email' => null]]);

        // A lifetime which is not the one hour every other test here uses, so that issuance ignoring the
        // interval it was built with and hardcoding an hour would show up.
        $this->sut(accessTokenTtl: new DateInterval('PT25M'))
            ->completeAuthorizationRequest($authorizationRequest);

        $this->assertSame($client, $this->accessTokenArguments[1]);
        $this->assertSame(['userinfo' => ['email' => null]], $this->accessTokenArguments[6]);
        $this->assertEqualsWithDelta(time() + 1500, $this->accessTokenArguments[3]->getTimestamp(), 5);
    }


    /**
     * The first guard on the issued access token. It cannot fire in production, since the factory's declared
     * return type is AccessTokenEntity and that satisfies it, but issueAccessToken() is declared to return
     * the wider AccessTokenEntityInterface, so a grant with that one method stubbed reaches it. It is pinned
     * so that widening the factory's return type later does not quietly take the check with it.
     */
    public function testAnIssuedAccessTokenWithNoStringRepresentationIsRejected(): void
    {
        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains(EntityStringRepresentationInterface::class),
                ['client_id' => self::CLIENT_ID],
            );

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage(EntityStringRepresentationInterface::class);

        $this->sutIssuing($this->createMock(AccessTokenEntityInterface::class))
            ->completeAuthorizationRequest($this->authorizationRequest());
    }


    /**
     * The response mode the request negotiated is the one the response is built with: the query mode puts the
     * parameters in the query string rather than the fragment.
     */
    public function testTheResponseIsBuiltWithTheResponseModeTheRequestCarries(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt('the-id-token');

        $location = $this->locationOf($this->completed(
            $this->authorizationRequest(responseMode: new QueryResponseMode()),
        ));

        $this->assertStringStartsWith(self::REDIRECT_URI . '?', $location);
        $this->assertSame('the-id-token', $this->paramsIn($location, PHP_URL_QUERY)['id_token']);
    }


    /**
     * With no negotiated response mode the implicit flow falls back to the fragment, which is where the
     * specification puts these parameters by default -- and it matters, because a query string would put the
     * ID Token into server logs and Referer headers.
     */
    public function testTheResponseFallsBackToTheFragmentWhenNoResponseModeWasNegotiated(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt('the-id-token');

        $location = $this->locationOf($this->completed($this->authorizationRequest()));

        $this->assertStringStartsWith(self::REDIRECT_URI . '#', $location);
        $this->assertSame('the-id-token', $this->paramsIn($location, PHP_URL_FRAGMENT)['id_token']);
    }


    /**
     * The redirect URI on the request was validated against the client's registered set before it got here,
     * and it is the one the response goes to. The client's registered URI is deliberately a different value,
     * so a response built at the registered URI instead lands somewhere this assertion can see.
     */
    public function testTheResponseGoesToTheRedirectUriTheRequestCarries(): void
    {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $location = $this->locationOf($this->completed($this->authorizationRequest()));

        $this->assertStringStartsWith(self::REDIRECT_URI . '#', $location);
    }


    /**
     * A request which never carried a redirect URI is answered at the one the client registered. Where the
     * client registered several, the first is used, which is the same choice the OAuth2 library makes.
     *
     * @param string|string[] $registered
     */
    #[DataProvider('registeredRedirectUriProvider')]
    public function testTheResponseGoesToTheRegisteredRedirectUriWhenTheRequestHasNone(
        array|string $registered,
        string $expected,
    ): void {
        $this->scopesAreFinalizedAs(new ScopeEntity('openid'));
        $this->accessTokenIsIssued();
        $this->idTokenIsBuilt();

        $location = $this->locationOf($this->completed($this->authorizationRequest(
            client: $this->clientMock($registered),
            redirectUri: null,
        )));

        $this->assertStringStartsWith($expected . '#', $location);
    }


    /**
     * @return array<string,array{0:string|string[],1:string}>
     */
    public static function registeredRedirectUriProvider(): array
    {
        return [
            'the first of several registered URIs' => [
                ['https://rp.example.org/first', 'https://rp.example.org/second'],
                'https://rp.example.org/first',
            ],
            'the single registered URI' => [
                'https://rp.example.org/only',
                'https://rp.example.org/only',
            ],
        ];
    }


    /**
     * Drive validateAuthorizationRequestWithRequestRules() with a full set of rule results.
     *
     * The method reads four results the caller resolved before it ran, and eleven out of the bag check()
     * hands back -- ten produced by the rules it just ran, plus the response mode, which is one of the four
     * read a second time. Most of the reads use getOrFail(), so every one of those results has to be there,
     * or a test fails on a missing key instead of on the behaviour it is about. `$ruleResults` overrides
     * individual defaults by rule class and `$withoutRules` removes them, which is how the optional ones
     * are tested as absent.
     *
     * @param array<class-string,mixed> $ruleResults
     * @param class-string[] $withoutRules
     */
    private function validatedAuthorizationRequest(
        array $ruleResults = [],
        array $withoutRules = [],
        ?ClientEntity $client = null,
        ?string $state = self::STATE,
    ): AuthorizationRequest {
        $defaults = [
            ScopeRule::class => [new ScopeEntity('openid'), new ScopeEntity('profile')],
            RequiredNonceRule::class => self::NONCE,
            MaxAgeRule::class => self::AUTH_TIME,
            RequestedClaimsRule::class => ['userinfo' => ['email' => null]],
            AddClaimsToIdTokenRule::class => true,
            ResponseTypeRule::class => 'id_token token',
            AcrValuesRule::class => ['urn:acr:from-the-acr-rule'],
            UiLocalesRule::class => 'en-GB',
            LoginHintRule::class => 'login-hint-from-the-rule',
            IdTokenHintRule::class => $this->idTokenHintMock('subject-from-the-id-token-hint'),
            ResponseModeRule::class => $this->checkedResponseMode,
        ];

        $checked = new ResultBag();
        $results = array_diff_key(array_merge($defaults, $ruleResults), array_flip($withoutRules));
        foreach ($results as $rule => $value) {
            // A rule class that is not imported still yields a `::class` string, just one in this namespace,
            // and the bag would then be missing an entry the grant asks for. Fail on the cause instead.
            $this->assertTrue(class_exists($rule), sprintf('Rule class "%s" does not exist.', $rule));

            $checked->add(new Result($rule, $value));
        }

        $this->requestRulesManagerMock->method('setData')
            ->willReturnCallback(function (string $key, string $value): void {
                $this->publishedData[$key] = $value;
            });

        $this->requestRulesManagerMock->method('predefineResultBag')
            ->willReturnCallback(function (ResultBagInterface $resultBag): void {
                $this->predefinedResultBag = $resultBag;
            });

        $this->requestRulesManagerMock->method('check')
            ->willReturnCallback(function (...$arguments) use ($checked): ResultBagInterface {
                $this->checkArguments = $arguments;
                // Snapshotted here rather than read after the call returns: a publication moved to after the
                // rules have run is of no use to them, and would otherwise still be found by the assertion.
                $this->dataAtCheckTime = $this->publishedData;
                $this->predefinedAtCheckTime = $this->predefinedResultBag;

                return $checked;
            });

        // What the caller has already resolved by the time this method runs.
        $this->incomingResultBag = new ResultBag();
        $this->incomingResultBag->add(new Result(ClientRedirectUriRule::class, self::REDIRECT_URI));
        $this->incomingResultBag->add(new Result(StateRule::class, $state));
        $this->incomingResultBag->add(new Result(ClientRule::class, $client ?? $this->clientMock()));
        $this->incomingResultBag->add(new Result(ResponseModeRule::class, $this->incomingResponseMode));

        $authorizationRequest = $this->sut()->validateAuthorizationRequestWithRequestRules(
            $this->serverRequestMock,
            $this->incomingResultBag,
        );
        $this->assertInstanceOf(AuthorizationRequest::class, $authorizationRequest);

        return $authorizationRequest;
    }


    /**
     * An authorization request in the state the authorization screen leaves it in: a client, a redirect URI,
     * an authenticated user and an approval. Individual tests take it back apart.
     */
    private function authorizationRequest(
        ?ClientEntity $client = null,
        ?string $redirectUri = self::REDIRECT_URI,
        string $responseType = 'id_token',
        ?ResponseModeInterface $responseMode = null,
        bool $isApproved = true,
        bool $withUser = true,
        ?string $state = self::STATE,
    ): AuthorizationRequest {
        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setClient($client ?? $this->clientMock());
        $authorizationRequest->setRedirectUri($redirectUri);
        $authorizationRequest->setScopes([new ScopeEntity('openid')]);
        $authorizationRequest->setAuthorizationApproved($isApproved);
        $authorizationRequest->setNonce(self::NONCE);

        if ($state !== null) {
            $authorizationRequest->setState($state);
        }

        $authorizationRequest->setResponseType($responseType);

        if ($withUser) {
            $authorizationRequest->setUser(
                new UserEntity(self::USER_ID, new DateTimeImmutable(), new DateTimeImmutable()),
            );
        }

        if ($responseMode !== null) {
            $authorizationRequest->setResponseMode($responseMode);
        }

        return $authorizationRequest;
    }


    /**
     * The registered redirect URI defaults to a different value from the one on the request. With the same
     * value in both, getRedirectUrl() preferring the request's URI -- and the validation half taking the
     * redirect URI off ClientRedirectUriRule rather than off the client -- would be indistinguishable from
     * the opposite behaviour.
     *
     * @param string|string[] $redirectUri
     */
    private function clientMock(
        array|string $redirectUri = self::REGISTERED_REDIRECT_URI,
    ): ClientEntity&MockObject {
        $client = $this->createMock(ClientEntity::class);
        $client->method('getIdentifier')->willReturn(self::CLIENT_ID);
        $client->method('getRedirectUri')->willReturn($redirectUri);

        return $client;
    }


    /**
     * A grant whose issueAccessToken() hands back the given token instead of building one, which is the only
     * way to put a token the type guards reject in front of them.
     */
    private function sutIssuing(AccessTokenEntityInterface $accessToken): ImplicitGrant&MockObject
    {
        $sut = $this->getMockBuilder(ImplicitGrant::class)
            ->setConstructorArgs([
                $this->idTokenBuilderMock,
                $this->accessTokenTtl1h,
                $this->accessTokenRepositoryMock,
                $this->requestRulesManagerMock,
                $this->requestParamsResolverMock,
                $this->accessTokenEntityFactoryMock,
                $this->loggerServiceMock,
            ])
            ->onlyMethods(['issueAccessToken'])
            ->getMock();

        $sut->setScopeRepository($this->scopeRepositoryMock);
        $sut->setDefaultScope(self::DEFAULT_SCOPE);
        $sut->method('issueAccessToken')->willReturn($accessToken);

        return $sut;
    }


    private function idTokenHintMock(string $subject): IdTokenHint&MockObject
    {
        $idTokenHint = $this->createMock(IdTokenHint::class);
        $idTokenHint->method('getSubject')->willReturn($subject);

        return $idTokenHint;
    }


    /**
     * The access token the factory hands back, with a known remaining lifetime so `expires_in` is checkable.
     */
    private function accessTokenIsIssued(
        string $token = 'access-token-string',
        int $lifetimeSeconds = 3600,
    ): AccessTokenEntity&MockObject {
        $accessToken = $this->createMock(AccessTokenEntity::class);
        $accessToken->method('toString')->willReturn($token);
        $accessToken->method('getExpiryDateTime')
            ->willReturn(new DateTimeImmutable('@' . (time() + $lifetimeSeconds)));

        // The grant passes several of these by name; PHPUnit binds them to the mocked signature and records
        // the invocation positionally, so they are read back by position below.
        $this->accessTokenEntityFactoryMock->method('fromData')
            ->willReturnCallback(function (...$arguments) use ($accessToken): AccessTokenEntity {
                $this->accessTokenArguments = $arguments;

                return $accessToken;
            });

        return $accessToken;
    }


    private function idTokenIsBuilt(string $token = 'id-token-string'): void
    {
        $idToken = $this->createMock(IdToken::class);
        $idToken->method('getToken')->willReturn($token);

        $this->idTokenBuilderMock->method('buildFor')
            ->willReturnCallback(function (...$arguments) use ($idToken): IdToken {
                $this->idTokenArguments = $arguments;

                return $idToken;
            });
    }


    private function scopesAreFinalizedAs(ScopeEntityInterface ...$scopes): void
    {
        $this->scopeRepositoryMock->method('finalizeScopes')
            ->willReturnCallback(function (...$arguments) use ($scopes): array {
                $this->finalizeScopesArguments = $arguments;

                return $scopes;
            });
    }


    private function completed(AuthorizationRequest $authorizationRequest): AbstractResponseType
    {
        $response = $this->sut()->completeAuthorizationRequest($authorizationRequest);
        $this->assertInstanceOf(AbstractResponseType::class, $response);
        /** @var \League\OAuth2\Server\ResponseTypes\AbstractResponseType $response */

        return $response;
    }


    private function locationOf(AbstractResponseType $response): string
    {
        return $response->generateHttpResponse(new Response())->getHeaderLine('location');
    }


    /**
     * @return array<string,string>
     */
    private function paramsIn(string $location, int $component): array
    {
        $part = parse_url($location, $component);
        parse_str(is_string($part) ? $part : '', $params);

        /** @var array<string,string> $params */
        return $params;
    }
}
