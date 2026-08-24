<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers;

use Exception;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\BadRequest;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Controllers\EndSessionController;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\RequestTypes\LogoutRequest;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreBuilder;
use SimpleSAML\Module\oidc\Stores\Session\LogoutTicketStoreDb;
use SimpleSAML\Module\oidc\Utils\UiLocalesResolver;
use SimpleSAML\OpenID\Core\IdToken;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * @covers \SimpleSAML\Module\oidc\Controllers\EndSessionController
 */
#[AllowMockObjectsWithoutExpectations]
class EndSessionControllerTest extends TestCase
{
    protected Stub $authorizationServerStub;

    protected Stub $authenticationServiceStub;

    protected Stub $sessionServiceStub;

    protected Stub $sessionLogoutTicketStoreBuilderStub;

    protected Stub $serverRequestStub;

    protected Stub $idTokenHintStub;

    protected Stub $logoutRequestStub;

    protected Stub $dataSetStub;

    protected MockObject $currentSessionMock;

    protected MockObject $sessionMock;

    protected array $dataSet = ['sid' => '123'];

    protected Stub $loggerServiceStub;

    protected Stub $sessionLogoutTicketStoreDbStub;

    protected MockObject $loggerServiceMock;

    protected Stub $templateFactoryStub;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $errorResponderMock;

    protected Stub $uiLocalesResolverStub;


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
        $this->sessionLogoutTicketStoreDbStub = $this->createStub(LogoutTicketStoreDb::class);
        $this->templateFactoryStub = $this->createStub(TemplateFactory::class);

        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);

        $this->uiLocalesResolverStub = $this->createStub(UiLocalesResolver::class);
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
        $this->authorizationServerStub->method('validateLogoutRequest')
            ->willThrowException(new BadRequest('Invalid parameter provided.'));

        $this->expectException(BadRequest::class);

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCallLogoutForSessionIdInIdTokenHint(): void
    {
        $this->currentSessionMock->method('getSessionId')->willReturn('currentSession123');
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $this->sessionServiceStub->method('getSessionById')->willReturn($this->sessionMock);
        $this->idTokenHintStub->method('getPayload')->willReturn($this->dataSet);
        $this->idTokenHintStub->method('getPayloadClaim')
            ->willReturn('123');
        $this->logoutRequestStub->method('getIdTokenHint')->willReturn($this->idTokenHintStub);
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->sessionLogoutTicketStoreBuilderStub->method('getInstance')
            ->willReturn($this->sessionLogoutTicketStoreDbStub);

        $this->sessionMock->expects($this->exactly(2))
            ->method('doLogout')
            ->with($this->callback(fn($authId) => in_array($authId, ['authId1', 'authId2'])));

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogsIfSessionFromIdTokenHintNotFound(): void
    {
        $this->currentSessionMock->method('getSessionId')->willReturn('currentSession123');
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->sessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);
        $this->sessionServiceStub->method('getSessionById')->willThrowException(new Exception());
        $this->idTokenHintStub->method('getPayload')->willReturn($this->dataSet);
        $this->idTokenHintStub->method('getPayloadClaim')
            ->willReturn('123');
        $this->logoutRequestStub->method('getIdTokenHint')->willReturn($this->idTokenHintStub);
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->sessionLogoutTicketStoreBuilderStub->method('getInstance')
            ->willReturn($this->sessionLogoutTicketStoreDbStub);

        $this->loggerServiceMock->expects($this->once())
            ->method('warning');

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLogoutCalledOnCurrentSession(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn(['authId1', 'authId2']);

        $this->currentSessionMock->expects($this->exactly(2))
            ->method('doLogout')
            ->with($this->callback(fn($authId) => in_array($authId, ['authId1', 'authId2'])));

        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);

        $this->mock()->__invoke($this->serverRequestStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReturnsRedirectResponseIfPostLogoutRedirectUriIsSet(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->logoutRequestStub->method('getPostLogoutRedirectUri')->willReturn('https://example.org');
        $this->logoutRequestStub->method('getState')->willReturn('state123');
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);

        $this->assertInstanceOf(RedirectResponse::class, $this->mock()->__invoke($this->serverRequestStub));
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReturnsResponse(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);

        $this->assertInstanceOf(Response::class, $this->mock()->__invoke($this->serverRequestStub));
    }


    public function testLogoutHandler(): never
    {
        $this->markTestIncomplete();
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRendersLogoutPageInResolvedUiLanguage(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->logoutRequestStub->method('getUiLocales')->willReturn('hr en');
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->uiLocalesResolverStub->method('resolve')->willReturn('hr');

        $this->assertSame('hr', $this->captureRenderedTemplateLanguage());
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRendersLogoutPageWithoutLanguageWhenNoneResolved(): void
    {
        $this->currentSessionMock->method('getAuthorities')->willReturn([]);
        $this->sessionServiceStub->method('getCurrentSession')->willReturn($this->currentSessionMock);
        $this->logoutRequestStub->method('getUiLocales')->willReturn('de');
        $this->authorizationServerStub->method('validateLogoutRequest')->willReturn($this->logoutRequestStub);
        $this->uiLocalesResolverStub->method('resolve')->willReturn(null);

        $this->assertNull($this->captureRenderedTemplateLanguage());
    }


    /**
     * Invoke the controller with a TemplateFactory mock and return the language passed to the rendered
     * logout template.
     *
     * @throws \Throwable
     * @throws \SimpleSAML\Error\BadRequest
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    private function captureRenderedTemplateLanguage(): ?string
    {
        $templateStub = $this->createStub(Template::class);
        $capturedLanguage = null;

        $templateFactoryMock = $this->createMock(TemplateFactory::class);
        $templateFactoryMock->method('build')->willReturnCallback(
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
                &$capturedLanguage,
                $templateStub,
            ): Template {
                $capturedLanguage = $language;
                return $templateStub;
            },
        );

        $this->mock($templateFactoryMock)->__invoke($this->serverRequestStub);

        return $capturedLanguage;
    }
}
