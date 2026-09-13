<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Logger;
use SimpleSAML\Logger\LoggingHandlerInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\EndSessionController;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\Associations\RelyingPartyAssociation;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreInterface;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\Session;
use SimpleSAML\SessionHandler;
use SimpleSAML\XHTML\Template;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * The static logoutHandler() is covered here as well. It reaches its collaborators through globals: the
 * current session through Session::getSessionFromRequest(), the sessions named by logout tickets through
 * Session::getSession(), the ticket store through LogoutTicketStoreBuilder::getStaticInstance() and the
 * logger through LoggerService::getInstance(). Both session lookups go through the one SessionHandler that
 * SimpleSAMLphp caches, behind Session's own in-memory caches of the current and of the loaded sessions; with
 * those caches cleared, a handler double installed there stands in for the whole session store. The ticket
 * store is set the way the builder's constructor sets it for the process, and the logger is captured.
 * tearDown() clears all of it again. Which associations the handler passes on to BackChannelLogoutHandler is
 * not observable, since it constructs that handler itself; what is observable, and pinned, is which sessions
 * it clears and which tickets it deletes. BackChannelLogoutHandlerTest covers what happens to the
 * associations from there.
 */
#[CoversClass(EndSessionController::class)]
#[AllowMockObjectsWithoutExpectations]
class EndSessionControllerTest extends TestCase
{
    protected const string CURRENT_SESSION_ID = 'currentSession123';

    protected const string HINTED_SESSION_ID = '123';

    protected const string POST_LOGOUT_REDIRECT_URI = 'https://rp.example.org/after';


    protected Stub $authorizationServerStub;

    protected Stub $sessionServiceStub;

    protected Stub $sessionLogoutTicketStoreBuilderStub;

    protected Stub $serverRequestStub;

    protected Stub $idTokenHintStub;

    protected Stub $logoutRequestStub;

    protected MockObject $currentSessionMock;

    protected MockObject $sessionMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $sessionLogoutTicketStoreMock;

    protected Stub $templateFactoryStub;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $errorResponderMock;

    protected Stub $uiLocalesResolverStub;

    /** @var list<string> */
    protected array $debugLines = [];

    /** @var array<string, array> The context each debug line was logged with, by message. */
    protected array $debugContexts = [];

    /**
     * What the session handler double holds, by session ID: a session, null for one that is gone, or a
     * throwable for one the store cannot load.
     *
     * @var array<string, \SimpleSAML\Session|\Throwable|null>
     */
    protected array $storedSessions = [];

    /** @var list<string> The session IDs the handler double was asked to load, in order. */
    protected array $loadedSessionIds = [];


    /**
     * @throws \PHPUnit\Framework\MockObject\Exception
     */
    public function setUp(): void
    {
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->sessionServiceStub = $this->createStub(SessionService::class);
        $this->sessionLogoutTicketStoreBuilderStub = $this->createStub(LogoutTicketStoreBuilder::class);
        $this->serverRequestStub = $this->createStub(ServerRequest::class);
        $this->currentSessionMock = $this->createMock(Session::class);
        $this->sessionMock = $this->createMock(Session::class);
        $this->logoutRequestStub = $this->createStub(LogoutRequest::class);
        $this->idTokenHintStub = $this->createStub(IdToken::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->sessionLogoutTicketStoreMock = $this->createMock(LogoutTicketStoreInterface::class);
        $this->templateFactoryStub = $this->createStub(TemplateFactory::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
        $this->uiLocalesResolverStub = $this->createStub(UiLocalesResolver::class);

        $this->currentSessionMock->method('getSessionId')->willReturn(self::CURRENT_SESSION_ID);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->sessionLogoutTicketStoreBuilderStub->method('getInstance')
            ->willReturn($this->sessionLogoutTicketStoreMock);
        $this->loggerServiceMock->method('debug')->willReturnCallback(
            function (string $message, array $context = []): void {
                $this->debugLines[] = $message;
                $this->debugContexts[$message] = $context;
            },
        );
    }


    /**
     * The globals the logoutHandler() tests install, cleared again so that no later test finds a double
     * behind SimpleSAMLphp's session, its session handler, the ticket store or the logger. Cleared rather than
     * restored: each of them is rebuilt from configuration on its next use, and the track ID which
     * Session::load() took from the session double goes back to the value a fresh process starts with.
     */
    public function tearDown(): void
    {
        Session::clearInternalState();
        self::setStaticProperty(SessionHandler::class, 'sessionHandler', null);
        self::setStaticProperty(LogoutTicketStoreBuilder::class, 'sessionLogoutTicketStore', null);
        Logger::setLoggingHandler(null);
        Logger::setTrackId(Logger::NO_TRACKID);
        Logger::setCaptureLog(false);
        Logger::clearCapturedLog();
    }


    protected function mock(?TemplateFactory $templateFactory = null): EndSessionController
    {
        return new EndSessionController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $templateFactory ?? $this->templateFactoryStub,
            $this->psrHttpBridgeMock,
            $this->errorResponderMock,
            $this->uiLocalesResolverStub,
        );
    }


    public function testConstruct(): void
    {
        $this->assertInstanceOf(
            EndSessionController::class,
            $this->mock(),
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testInvokeThrowsForInvalidLogoutRequest(): void
    {
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->authorizationServerStub->method('validateLogoutRequest')
            ->willThrowException(new BadRequest('Invalid parameter provided.'));

        $this->expectException(BadRequest::class);

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * The flag is what the static logoutHandler() checks when SimpleSAMLphp calls it back during doLogout(),
     * so it has to be up while the auth sources log out and down again before anything else can trigger the
     * handler.
     *
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogsOutEveryAuthSourceOfTheCurrentSessionWhileFlaggedAsOidcInitiated(): void
    {
        $timeline = [];
        $sessionServiceMock = $this->sessionServiceMock();
        $sessionServiceMock->expects($this->exactly(2))->method('setIsOidcInitiatedLogout')
            ->willReturnCallback(function (bool $isOidcInitiatedLogout) use (&$timeline): void {
                $timeline[] = 'oidc initiated: ' . var_export($isOidcInitiatedLogout, true);
            });
        $this->currentSessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $this->currentSessionMock->expects($this->exactly(2))->method('doLogout')
            ->willReturnCallback(function (string $authority) use (&$timeline): void {
                $timeline[] = 'logout: ' . $authority;
            });

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertSame(
            ['oidc initiated: true', 'logout: authId1', 'logout: authId2', 'oidc initiated: false'],
            $timeline,
        );
        $this->assertContains('Current session authorities: authId1, authId2', $this->debugLines);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogsOutEveryAuthSourceOfTheHintedSessionAndLeavesATicketForIt(): void
    {
        $this->hintSession();
        $this->sessionServiceMock()->expects($this->once())->method('getSessionById')
            ->with(self::HINTED_SESSION_ID)->willReturn($this->sessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $loggedOut = [];
        $this->sessionMock->expects($this->exactly(2))->method('doLogout')
            ->willReturnCallback(function (string $authority) use (&$loggedOut): void {
                $loggedOut[] = $authority;
            });
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('add')->with(self::HINTED_SESSION_ID);
        $this->currentSessionMock->expects($this->never())->method('doLogout');

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertSame(['authId1', 'authId2'], $loggedOut);
        $this->assertContains('Valid session authorities: authId1, authId2', $this->debugLines);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testDoesNotLookUpTheHintedSessionWhenItIsTheCurrentOne(): void
    {
        $this->hintSession(self::CURRENT_SESSION_ID);
        $this->sessionServiceMock()->expects($this->never())->method('getSessionById');
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('add');

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertContains('EndSession: ID Token Hint Session ID: \'currentSession123\'', $this->debugLines);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('unusableSidProvider')]
    public function testIgnoresAnIdTokenHintWhoseSidIsNotAUsableString(mixed $sid): void
    {
        $this->hintSession($sid);
        $this->sessionServiceMock()->expects($this->never())->method('getSessionById');

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertContains('EndSession: ID Token Hint Session ID: NULL', $this->debugLines);
    }


    public static function unusableSidProvider(): array
    {
        // An absent claim is null before the normalisation runs, so it is not a case of it.
        return ['empty' => [''], 'not a string' => [123]];
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogsWhenTheHintedSessionDoesNotExist(): void
    {
        $this->hintSession();
        $this->sessionServiceStub->method('getSessionById')->willReturn(null);
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('add');

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertContains('Session not found for ID: 123', $this->debugLines);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogsWhenTheHintedSessionHasNoAuthorities(): void
    {
        $this->hintSession();
        $this->sessionServiceStub->method('getSessionById')->willReturn($this->sessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionMock->expects($this->never())->method('doLogout');
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('add');

        $this->mock()->__invoke($this->serverRequestStub);

        $this->assertContains('Session authorities not found for ID: 123', $this->debugLines);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testWarnsWhenTheHintedSessionCannotBeLoadedAndStillLogsOutTheCurrentOne(): void
    {
        $this->hintSession();
        $this->sessionServiceStub->method('getSessionById')->willThrowException(new Exception('store is down'));
        $this->loggerServiceMock->expects($this->once())->method('warning')
            ->with('Logout: could not get session with ID 123, error: store is down', []);
        $this->currentSessionMock->method('getAuthorities')->willReturn(['authId1']);
        $this->currentSessionMock->expects($this->once())->method('doLogout')->with('authId1');

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('logoutActionProvider')]
    public function testTellsTheLogoutPageWhetherAnyAuthSourceWasLoggedOut(
        array $currentAuthorities,
        array $hintedAuthorities,
        bool $wasLogoutActionCalled,
    ): void {
        $this->currentSessionMock->method('getAuthorities')->willReturn($currentAuthorities);
        $this->hintSession();
        $this->sessionMock->method('getAuthorities')->willReturn($hintedAuthorities);
        $this->sessionServiceStub->method('getSessionById')->willReturn($this->sessionMock);

        $this->assertSame(
            ['wasLogoutActionCalled' => $wasLogoutActionCalled],
            $this->captureRenderedTemplate()['data'],
        );
        $this->assertContains(
            'Was logout action called: ' . var_export($wasLogoutActionCalled, true),
            $this->debugLines,
        );
    }


    public static function logoutActionProvider(): array
    {
        return [
            'nothing to log out' => [[], [], false],
            'the current session' => [['authId1'], [], true],
            'only the hinted session' => [[], ['authId1'], true],
        ];
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRendersTheLogoutPageAsABarePageInTheResolvedLanguage(): void
    {
        $this->logoutRequestStub->method('getUiLocales')->willReturn('hr en');
        $uiLocalesResolverMock = $this->createMock(UiLocalesResolver::class);
        $uiLocalesResolverMock->expects($this->once())->method('resolve')->with('hr en')->willReturn('hr');
        $this->uiLocalesResolverStub = $uiLocalesResolverMock;

        $this->assertSame(
            [
                'templateName' => 'oidc:/logout.twig',
                'data' => ['wasLogoutActionCalled' => false],
                'activeHrefPath' => null,
                'includeDefaultMenuItems' => null,
                'showMenu' => false,
                'showModuleName' => false,
                'showSubPageTitle' => false,
                'language' => 'hr',
            ],
            $this->captureRenderedTemplate(),
        );
        $this->assertSame(
            ['uiLocales' => 'hr en', 'language' => 'hr'],
            $this->debugContexts['EndSessionController: resolved UI language based on ui_locales parameter.'],
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRendersTheLogoutPageWithoutLanguageWhenNoneResolved(): void
    {
        $this->logoutRequestStub->method('getUiLocales')->willReturn('de');
        $this->uiLocalesResolverStub->method('resolve')->willReturn(null);

        $this->assertNull($this->captureRenderedTemplate()['language']);
        $this->assertNotContains(
            'EndSessionController: resolved UI language based on ui_locales parameter.',
            $this->debugLines,
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('postLogoutRedirectProvider')]
    public function testRedirectsToThePostLogoutUriWithTheStateAppended(
        string $postLogoutRedirectUri,
        string $state,
        string $expectedTargetUrl,
    ): void {
        $this->logoutRequestStub->method('getPostLogoutRedirectUri')->willReturn($postLogoutRedirectUri);
        $this->logoutRequestStub->method('getState')->willReturn($state);
        $templateFactoryMock = $this->createMock(TemplateFactory::class);
        $templateFactoryMock->expects($this->never())->method('build');

        $response = $this->mock($templateFactoryMock)->__invoke($this->serverRequestStub);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame($expectedTargetUrl, $response->getTargetUrl());
        $this->assertContains('Appending logout request state: ' . $state, $this->debugLines);
    }


    public static function postLogoutRedirectProvider(): array
    {
        // The separator and the encoding are the two things a rewrite can get wrong; each case catches one of
        // them where the other cannot.
        return [
            'no query yet' => [
                self::POST_LOGOUT_REDIRECT_URI,
                'state123',
                self::POST_LOGOUT_REDIRECT_URI . '?state=state123',
            ],
            'a query already, and a state which needs encoding' => [
                self::POST_LOGOUT_REDIRECT_URI . '?x=1',
                'a b&c',
                self::POST_LOGOUT_REDIRECT_URI . '?x=1&state=a+b%26c',
            ],
        ];
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRedirectsToThePostLogoutUriAsGivenWhenThereIsNoState(): void
    {
        $this->logoutRequestStub->method('getPostLogoutRedirectUri')
            ->willReturn(self::POST_LOGOUT_REDIRECT_URI . '?x=1');
        $this->logoutRequestStub->method('getState')->willReturn(null);

        $response = $this->mock()->__invoke($this->serverRequestStub);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame(self::POST_LOGOUT_REDIRECT_URI . '?x=1', $response->getTargetUrl());
        $this->assertContains('No state provided for post logout', $this->debugLines);
    }


    /**
     * @throws \Throwable
     */
    public function testEndSessionBridgesTheSymfonyRequestAndReturnsTheHandlerResponse(): void
    {
        $symfonyRequest = new Request();
        $psrHttpFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrHttpFactoryMock->expects($this->once())->method('createRequest')
            ->with($this->identicalTo($symfonyRequest))->willReturn($this->serverRequestStub);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrHttpFactoryMock);
        $authorizationServerMock = $this->createMock(AuthorizationServer::class);
        $authorizationServerMock->expects($this->once())->method('validateLogoutRequest')
            ->with($this->identicalTo($this->serverRequestStub))->willReturn($this->logoutRequestStub);
        $this->authorizationServerStub = $authorizationServerMock;
        $this->logoutRequestStub->method('getPostLogoutRedirectUri')->willReturn(self::POST_LOGOUT_REDIRECT_URI);
        $this->errorResponderMock->expects($this->never())->method('forException');

        $response = $this->mock()->endSession($symfonyRequest);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame(self::POST_LOGOUT_REDIRECT_URI, $response->getTargetUrl());
    }


    /**
     * @throws \Throwable
     */
    public function testEndSessionAnswersAnOAuthServerExceptionThroughTheErrorResponder(): void
    {
        $exception = OAuthServerException::invalidRequest('id_token_hint');
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->authorizationServerStub->method('validateLogoutRequest')->willThrowException($exception);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($this->createStub(PsrHttpFactory::class));
        $errorResponse = new Response('', 400);
        $this->errorResponderMock->expects($this->once())->method('forException')
            ->with($this->identicalTo($exception))->willReturn($errorResponse);

        $this->assertSame($errorResponse, $this->mock()->endSession(new Request()));
    }


    /**
     * @throws \Throwable
     */
    public function testEndSessionLetsAnyOtherFailureThrough(): void
    {
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->authorizationServerStub->method('validateLogoutRequest')
            ->willThrowException(new BadRequest('Invalid parameter provided.'));
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($this->createStub(PsrHttpFactory::class));
        $this->errorResponderMock->expects($this->never())->method('forException');

        $this->expectException(BadRequest::class);

        $this->mock()->endSession(new Request());
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerDoesNothingUnlessTheLogoutWasOidcInitiated(): void
    {
        $this->installLogoutHandlerGlobals([
            SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS => [$this->association()],
        ]);
        $this->currentSessionMock->expects($this->never())->method('setData');
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('getAll');
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('deleteMultiple');

        EndSessionController::logoutHandler();

        $this->assertSame([self::CURRENT_SESSION_ID], $this->loadedSessionIds);
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerClearsTheCurrentSessionAssociationsWhenThereAreNoTickets(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $this->expectAssociationsCleared($this->currentSessionMock);
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([]);
        $this->sessionLogoutTicketStoreMock->expects($this->never())->method('deleteMultiple');

        EndSessionController::logoutHandler();

        $this->assertSame([self::CURRENT_SESSION_ID], $this->loadedSessionIds);
        $this->assertSame([], $this->ticketWarnings());
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerSkipsATicketForTheCurrentSessionButStillDeletesIt(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $this->expectAssociationsCleared($this->currentSessionMock);
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([['sid' => self::CURRENT_SESSION_ID]]);
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('deleteMultiple')
            ->with([self::CURRENT_SESSION_ID]);

        EndSessionController::logoutHandler();

        // The skip shows as the associations being gathered and cleared once, as the current session's, and
        // not again for the ticket: expectAssociationsCleared() allows exactly one clearing. The session is not
        // loaded a second time either way, since Session caches it after the first load.
        $this->assertSame([self::CURRENT_SESSION_ID], $this->loadedSessionIds);
        $this->assertSame([], $this->ticketWarnings());
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerClearsATicketedSessionAsWellAndDeletesItsTicket(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $ticketedSession = $this->storedSession('ticketedSession456', [
            SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS => [$this->association('ticketedSession456')],
        ]);
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([['sid' => 'ticketedSession456']]);
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('deleteMultiple')
            ->with(['ticketedSession456']);
        $this->expectAssociationsCleared($this->currentSessionMock);
        $this->expectAssociationsCleared($ticketedSession);

        EndSessionController::logoutHandler();

        $this->assertSame([self::CURRENT_SESSION_ID, 'ticketedSession456'], $this->loadedSessionIds);
        $this->assertSame([], $this->ticketWarnings());
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerDeletesTheTicketOfASessionWhichIsGone(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $this->storedSessions['goneSession789'] = null;
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([['sid' => 'goneSession789']]);
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('deleteMultiple')
            ->with(['goneSession789']);
        $this->expectAssociationsCleared($this->currentSessionMock);

        EndSessionController::logoutHandler();

        $this->assertSame([self::CURRENT_SESSION_ID, 'goneSession789'], $this->loadedSessionIds);
        $this->assertSame([], $this->ticketWarnings());
    }


    /**
     * @throws \Exception
     */
    public function testLogoutHandlerWarnsWhenATicketedSessionCannotBeLoadedAndStillDeletesItsTicket(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $this->storedSessions['brokenSession000'] = new Exception('store is down');
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([['sid' => 'brokenSession000']]);
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('deleteMultiple')
            ->with(['brokenSession000']);
        $this->expectAssociationsCleared($this->currentSessionMock);

        EndSessionController::logoutHandler();

        $this->assertSame([self::CURRENT_SESSION_ID, 'brokenSession000'], $this->loadedSessionIds);
        $this->assertSame(
            ['Session Ticket Logout: could not get session with ID brokenSession000, error: store is down'],
            $this->ticketWarnings(),
        );
    }


    /**
     * Every ticket is deleted, in the order the store gave them, whatever became of its session.
     *
     * @throws \Exception
     */
    public function testLogoutHandlerHandlesEveryTicketOfOneLogoutTogether(): void
    {
        $this->installLogoutHandlerGlobals($this->oidcInitiatedWith([$this->association()]));
        $ticketedSession = $this->storedSession('ticketedSession456', [
            SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS => [$this->association('ticketedSession456')],
        ]);
        $this->storedSessions['goneSession789'] = null;
        $this->storedSessions['brokenSession000'] = new Exception('store is down');
        $this->sessionLogoutTicketStoreMock->method('getAll')->willReturn([
            ['sid' => self::CURRENT_SESSION_ID],
            ['sid' => 'ticketedSession456'],
            ['sid' => 'goneSession789'],
            ['sid' => 'brokenSession000'],
        ]);
        $this->sessionLogoutTicketStoreMock->expects($this->once())->method('deleteMultiple')
            ->with([self::CURRENT_SESSION_ID, 'ticketedSession456', 'goneSession789', 'brokenSession000']);
        $this->expectAssociationsCleared($this->currentSessionMock);
        $this->expectAssociationsCleared($ticketedSession);

        EndSessionController::logoutHandler();

        $this->assertSame(
            [self::CURRENT_SESSION_ID, 'ticketedSession456', 'goneSession789', 'brokenSession000'],
            $this->loadedSessionIds,
        );
        $this->assertSame(
            ['Session Ticket Logout: could not get session with ID brokenSession000, error: store is down'],
            $this->ticketWarnings(),
        );
    }


    /**
     * A logout request carrying an id_token_hint whose sid claim is the given value.
     */
    protected function hintSession(mixed $sid = self::HINTED_SESSION_ID): void
    {
        $this->idTokenHintStub->method('getPayloadClaim')->willReturn($sid);
        $this->logoutRequestStub->method('getIdTokenHint')->willReturn($this->idTokenHintStub);
    }


    /**
     * Replace the session service stub with a mock which can take expectations, wired to the same current
     * session.
     */
    protected function sessionServiceMock(): MockObject
    {
        $sessionServiceMock = $this->createMock(SessionService::class);
        $sessionServiceMock->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->sessionServiceStub = $sessionServiceMock;

        return $sessionServiceMock;
    }


    /**
     * Invoke the controller with a TemplateFactory mock and return every argument the logout template was
     * built with, by parameter name.
     *
     * @return array<string, mixed>
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function captureRenderedTemplate(): array
    {
        $templateStub = $this->createStub(Template::class);
        $captured = null;

        $templateFactoryMock = $this->createMock(TemplateFactory::class);
        $templateFactoryMock->expects($this->once())->method('build')->willReturnCallback(
            function (
                string $templateName,
                array $data = [],
                ?string $activeHrefPath = null,
                ?bool $includeDefaultMenuItems = null,
                ?bool $showMenu = null,
                ?bool $showModuleName = null,
                ?bool $showSubPageTitle = null,
                ?string $language = null,
            ) use (
                &$captured,
                $templateStub,
            ): Template {
                $captured = compact(
                    'templateName',
                    'data',
                    'activeHrefPath',
                    'includeDefaultMenuItems',
                    'showMenu',
                    'showModuleName',
                    'showSubPageTitle',
                    'language',
                );
                return $templateStub;
            },
        );

        $this->mock($templateFactoryMock)->__invoke($this->serverRequestStub);

        $this->assertIsArray($captured);

        return $captured;
    }


    /**
     * Put doubles behind the globals logoutHandler() reaches: the current session behind the session handler
     * SimpleSAMLphp caches, the ticket store behind the builder, and a capturing logger which sends nothing on.
     * Session's own caches are emptied first, so that every session comes from the handler double and not
     * from whatever an earlier test loaded.
     *
     * @param array<string, mixed> $currentSessionData The current session's oidc data, by data ID.
     */
    protected function installLogoutHandlerGlobals(array $currentSessionData): void
    {
        Session::clearInternalState();

        $this->currentSessionMock->method('getData')->willReturnCallback(
            fn(string $type, ?string $id): mixed => $type === SessionService::SESSION_DATA_TYPE ?
                ($currentSessionData[$id] ?? null) :
                null,
        );
        $this->storedSessions[self::CURRENT_SESSION_ID] = $this->currentSessionMock;

        $sessionHandlerMock = $this->createMock(SessionHandler::class);
        $sessionHandlerMock->method('getCookieSessionId')->willReturn(self::CURRENT_SESSION_ID);
        $sessionHandlerMock->method('loadSession')->willReturnCallback(
            function (?string $sessionId): ?Session {
                $this->loadedSessionIds[] = (string)$sessionId;
                $stored = $this->storedSessions[$sessionId] ?? null;
                if ($stored instanceof Throwable) {
                    throw $stored;
                }
                return $stored;
            },
        );
        self::setStaticProperty(SessionHandler::class, 'sessionHandler', $sessionHandlerMock);

        new LogoutTicketStoreBuilder($this->sessionLogoutTicketStoreMock);

        Logger::setLoggingHandler($this->createStub(LoggingHandlerInterface::class));
        Logger::setCaptureLog();
        Logger::clearCapturedLog();
    }


    /**
     * A session the handler double can load, holding the given oidc data.
     *
     * @param array<string, mixed> $data The session's oidc data, by data ID.
     */
    protected function storedSession(string $sessionId, array $data): MockObject
    {
        $session = $this->createMock(Session::class);
        $session->method('getSessionId')->willReturn($sessionId);
        $session->method('getData')->willReturnCallback(
            fn(string $type, ?string $id): mixed => $type === SessionService::SESSION_DATA_TYPE ?
                ($data[$id] ?? null) :
                null,
        );
        $this->storedSessions[$sessionId] = $session;

        return $session;
    }


    /**
     * The oidc data of a session whose logout was started through OIDC, with the given associations.
     *
     * @return array<string, mixed>
     */
    protected function oidcInitiatedWith(array $associations): array
    {
        return [
            SessionService::SESSION_DATA_ID_IS_OIDC_INITIATED_LOGOUT => true,
            SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS => $associations,
        ];
    }


    /**
     * An association without a back-channel logout URI, so that the BackChannelLogoutHandler the static
     * handler constructs has nothing to send.
     */
    protected function association(string $sessionId = self::CURRENT_SESSION_ID): RelyingPartyAssociation
    {
        return new RelyingPartyAssociation('client-1', 'user-1', $sessionId);
    }


    protected function expectAssociationsCleared(MockObject $session): void
    {
        $session->expects($this->once())->method('setData')->with(
            SessionService::SESSION_DATA_TYPE,
            SessionService::SESSION_DATA_ID_RP_ASSOCIATIONS,
            [],
            Session::DATA_TIMEOUT_SESSION_END,
        );
    }


    /**
     * The warnings the static handler logged about logout tickets, without the timestamp the capture adds.
     *
     * @return list<string>
     */
    protected function ticketWarnings(): array
    {
        $warnings = [];
        foreach (Logger::getCapturedLog() as $line) {
            $position = strpos($line, 'Session Ticket Logout:');
            if ($position !== false) {
                $warnings[] = substr($line, $position);
            }
        }

        return $warnings;
    }


    protected static function setStaticProperty(string $class, string $property, mixed $value): void
    {
        (new ReflectionProperty($class, $property))->setValue(null, $value);
    }
}
