<?php

namespace SimpleSAML\Test\Module\oidc\Controller;

use Exception;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Laminas\Diactoros\ServerRequest;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\UnencryptedToken;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Controller\LogoutController;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Store\SessionLogoutTicketStoreDb;
use SimpleSAML\Session;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Controller\LogoutController
 */
class LogoutControllerTest extends TestCase
{
    /**
     * @var mixed
     */
    protected $authorizationServerStub;
    /**
     * @var mixed
     */
    protected $authenticationServiceStub;
    /**
     * @var mixed
     */
    protected $sessionServiceStub;
    /**
     * @var mixed
     */
    protected $sessionLogoutTicketStoreBuilderStub;
    /**
     * @var mixed
     */
    protected $serverRequestStub;
    /**
     * @var mixed
     */
    protected $idTokenHintStub;
    /**
     * @var mixed
     */
    protected $logoutRequestStub;
    /**
     * @var mixed
     */
    protected $dataSetStub;
    /**
     * @var mixed
     */
    protected $currentSessionMock;
    /**
     * @var mixed
     */
    protected $sessionMock;
    /**
     * @var DataSet
     */
    protected DataSet $dataSet;
    /**
     * @var mixed
     */
    protected $loggerServiceStub;
    /**
     * @var mixed
     */
    protected $sessionLogoutTicketStoreDbStub;
    /**
     * @var mixed
     */
    protected $loggerServiceMock;
    /**
     * @var mixed
     */
    protected $templateFactoryStub;

    public function setUp(): void
    {
        $this->authorizationServerStub = $this->createStub(AuthorizationServer::class);
        $this->sessionServiceStub = $this->createStub(SessionService::class);
        $this->sessionLogoutTicketStoreBuilderStub = $this->createStub(SessionLogoutTicketStoreBuilder::class);
        $this->serverRequestStub = $this->createStub(ServerRequest::class);
        $this->currentSessionMock = $this->createMock(Session::class);
        $this->sessionMock = $this->createMock(Session::class);
        $this->logoutRequestStub = $this->createStub(LogoutRequest::class);
        $this->idTokenHintStub = $this->createStub(UnencryptedToken::class);
        $this->dataSet = new DataSet(['sid' => '123'], '');
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->sessionLogoutTicketStoreDbStub = $this->createStub(SessionLogoutTicketStoreDb::class);
        $this->templateFactoryStub = $this->createStub(TemplateFactory::class);
    }

    public function testConstruct(): void
    {
        $this->assertInstanceOf(
            LogoutController::class,
            new LogoutController(
                $this->authorizationServerStub,
                $this->sessionServiceStub,
                $this->sessionLogoutTicketStoreBuilderStub,
                $this->loggerServiceMock,
                $this->templateFactoryStub
            )
        );
    }

    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function testInvokeThrowsForInvalidLogoutRequest(): void
    {
        $this->authorizationServerStub->method('validateLogoutRequest')
            ->willThrowException(new BadRequest('Invalid parameter provided.'));

        $logoutController = new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        );

        $this->expectException(BadRequest::class);

        $logoutController->__invoke($this->serverRequestStub);
    }

    /**
     * @throws Throwable
     * @throws BadRequest
     * @throws OidcServerException
     */
    public function testCallLogoutForSessionIdInIdTokenHint(): void
    {
        $this->currentSessionMock->method('getSessionId')->willReturn('currentSession123');
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $this->sessionServiceStub->method('getSessionById')->willReturn($this->sessionMock);
        $this->idTokenHintStub->method('claims')->willReturn($this->dataSet);
        $this->logoutRequestStub->method('getIdTokenHint')->willReturn($this->idTokenHintStub);
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->sessionLogoutTicketStoreBuilderStub->method('getInstance')
            ->willReturn($this->sessionLogoutTicketStoreDbStub);

        $this->sessionMock->expects($this->exactly(2))
            ->method('doLogout')
            ->with($this->callback(function ($authId) {
                return in_array($authId, ['authId1', 'authId2']);
            }));

        (new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        ))->__invoke($this->serverRequestStub);
    }

    /**
     * @throws Throwable
     * @throws BadRequest
     * @throws OidcServerException
     */
    public function testLogsIfSessionFromIdTokenHintNotFound(): void
    {
        $this->currentSessionMock->method('getSessionId')->willReturn('currentSession123');
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $this->sessionServiceStub->method('getSessionById')->willThrowException(new Exception());
        $this->idTokenHintStub->method('claims')->willReturn($this->dataSet);
        $this->logoutRequestStub->method('getIdTokenHint')->willReturn($this->idTokenHintStub);
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->sessionLogoutTicketStoreBuilderStub->method('getInstance')
            ->willReturn($this->sessionLogoutTicketStoreDbStub);

        $this->loggerServiceMock->expects($this->once())
            ->method('warning');

        (new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        ))->__invoke($this->serverRequestStub);
    }

    /**
     * @throws Throwable
     * @throws BadRequest
     * @throws OidcServerException
     */
    public function testLogoutCalledOnCurrentSession(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);

        $this->currentSessionMock->expects($this->exactly(2))
            ->method('doLogout')
            ->with($this->callback(function ($authId) {
                return in_array($authId, ['authId1', 'authId2']);
            }));

        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);

        (new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        ))->__invoke($this->serverRequestStub);
    }

    /**
     * @throws Throwable
     * @throws BadRequest
     * @throws OidcServerException
     */
    public function testReturnsRedirectResponseIfPostLogoutRedirectUriIsSet(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->logoutRequestStub->method('getPostLogoutRedirectUri')->willReturn('https://example.org');
        $this->logoutRequestStub->method('getState')->willReturn('state123');
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);

        $logoutController = new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        );

        $this->assertInstanceOf(RedirectResponse::class, $logoutController->__invoke($this->serverRequestStub));
    }

    /**
     * @throws Throwable
     * @throws BadRequest
     * @throws OidcServerException
     */
    public function testReturnsResponse(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);

        $logoutController = new LogoutController(
            $this->authorizationServerStub,
            $this->sessionServiceStub,
            $this->sessionLogoutTicketStoreBuilderStub,
            $this->loggerServiceMock,
            $this->templateFactoryStub
        );

        $this->assertInstanceOf(Response::class, $logoutController->__invoke($this->serverRequestStub));
    }

    public function testLogoutHandler(): void
    {
        $this->markTestIncomplete();
    }
}
