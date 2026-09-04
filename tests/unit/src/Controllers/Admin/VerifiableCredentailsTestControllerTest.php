<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth\Source;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\VerifiableCredentailsTestController;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\SessionService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use SimpleSAML\Session;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(VerifiableCredentailsTestController::class)]
#[AllowMockObjectsWithoutExpectations]
class VerifiableCredentailsTestControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'university_degree';

    protected const string AUTH_SOURCE_ID = 'default-sp';

    protected const string OFFER_URI = 'openid-credential-offer://?credential_offer=%7B%22a%22%3A1%7D';

    protected const string PAGE_URL = 'https://op.example.org/module.php/oidc/admin/test/vci';


    protected MockObject $moduleConfigMock;

    protected MockObject $templateFactoryMock;

    protected MockObject $authorizationMock;

    protected MockObject $authSimpleFactoryMock;

    protected MockObject $sessionServiceMock;

    protected MockObject $sspBridgeMock;

    protected MockObject $routesMock;

    protected MockObject $credentialOfferUriFactoryMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $sessionMock;

    protected MockObject $authSimpleMock;

    /** @var array<string,mixed> The data the controller handed the template. */
    protected array $templateData = [];

    /**
     * What the request carries, read through a callback rather than re-stubbed per test: a mock keeps
     * the first matcher registered for a method, so a second stub would silently never fire.
     *
     * @var array<string,mixed>
     */
    protected array $requestParams = [];

    /** @var array<string,mixed> What the session already holds under the `vci` namespace. */
    protected array $sessionData = [];

    /** @var string[] */
    protected array $authSourceIds = ['admin', self::AUTH_SOURCE_ID];

    protected bool $isAuthenticated = true;

    protected bool $vciEnabled = true;

    /** @var string[] */
    protected array $credentialConfigurationIdsSupported = [self::CONFIGURATION_ID];


    protected function setUp(): void
    {
        $this->templateData = [];
        $this->requestParams = [];
        $this->sessionData = [];
        $this->authSourceIds = ['admin', self::AUTH_SOURCE_ID];
        $this->isAuthenticated = true;
        $this->vciEnabled = true;
        $this->credentialConfigurationIdsSupported = [self::CONFIGURATION_ID];

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturnCallback(fn(): bool => $this->vciEnabled);
        $this->moduleConfigMock->method('getVciCredentialConfigurationIdsSupported')
            ->willReturnCallback(fn(): array => $this->credentialConfigurationIdsSupported);
        $this->moduleConfigMock->method('getDefaultUsersEmailAttributeName')->willReturn('mail');

        $this->authorizationMock = $this->createMock(Authorization::class);

        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (string $templateName, array $data = []): Template {
                $this->templateData = $data;

                return $this->createMock(Template::class);
            },
        );

        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->authSimpleMock->method('isAuthenticated')->willReturnCallback(fn(): bool => $this->isAuthenticated);
        $this->authSimpleMock->method('getAttributes')->willReturn(['givenName' => ['John']]);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactoryMock->method('forAuthSourceId')->willReturn($this->authSimpleMock);

        $this->sessionMock = $this->createMock(Session::class);
        $this->sessionMock->method('getData')->willReturnCallback(
            fn(string $type, string $key): mixed => $this->sessionData[$key] ?? null,
        );
        $this->sessionServiceMock = $this->createMock(SessionService::class);
        $this->sessionServiceMock->method('getCurrentSession')->willReturn($this->sessionMock);

        $sourceMock = $this->createMock(Source::class);
        $sourceMock->method('getSources')->willReturnCallback(fn(): array => $this->authSourceIds);
        $authMock = $this->createMock(Auth::class);
        $authMock->method('source')->willReturn($sourceMock);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->sspBridgeMock->method('auth')->willReturn($authMock);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlAdminTestVerifiableCredentialIssuance')->willReturn(self::PAGE_URL);
        $this->routesMock->method('newRedirectResponseToModuleUrl')
            ->willReturn(new RedirectResponse(self::PAGE_URL));

        $this->credentialOfferUriFactoryMock = $this->createMock(CredentialOfferUriFactory::class);
        $this->credentialOfferUriFactoryMock->method('buildPreAuthorized')->willReturn(self::OFFER_URI);
        $this->credentialOfferUriFactoryMock->method('buildForAuthorization')->willReturn(self::OFFER_URI);

        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->requestParamsResolverMock->method('getFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(fn(string $param): mixed => $this->requestParams[$param] ?? null);
    }


    protected function sut(): VerifiableCredentailsTestController
    {
        return new VerifiableCredentailsTestController(
            $this->moduleConfigMock,
            $this->templateFactoryMock,
            $this->authorizationMock,
            $this->authSimpleFactoryMock,
            $this->sessionServiceMock,
            $this->sspBridgeMock,
            $this->routesMock,
            $this->credentialOfferUriFactoryMock,
            $this->requestParamsResolverMock,
        );
    }


    /**
     * @param array<string,mixed> $body
     */
    protected function request(array $body = [], string $method = Request::METHOD_GET): Request
    {
        $request = new Request([], $body);
        $request->setMethod($method);

        return $request;
    }


    /**
     * This page can start an authentication and mint a credential offer, so it is for an administrator
     * and the check runs before any of it - in the constructor, where the container reaches it.
     */
    public function testRequiresAnAdministrator(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdmin')->with(true);

        $this->sut();
    }


    /**
     * The page still renders when the feature is off, saying why. An administrator arriving to find out
     * whether issuance works is exactly the person who needs to be told it is disabled.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testReportsThatVerifiableCredentialsAreNotEnabled(): void
    {
        $this->vciEnabled = false;

        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertNotEmpty($this->templateData['setupErrors'] ?? []);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testReportsThatNoCredentialConfigurationsAreConfigured(): void
    {
        $this->credentialConfigurationIdsSupported = [];

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertNotEmpty($this->templateData['setupErrors'] ?? []);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testRendersTheFormWhenNothingHasBeenSubmitted(): void
    {
        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame([], $this->templateData['setupErrors'] ?? null);
        $this->assertArrayHasKey('credentialOfferUri', $this->templateData);
        $this->assertNull($this->templateData['credentialOfferUri']);
        $this->assertNull($this->templateData['credentialOfferQrUri']);
        $this->assertSame(
            [self::CONFIGURATION_ID],
            $this->templateData['credentialConfigurationIdsSupported'] ?? null,
        );
    }


    /**
     * The administrator authentication source is how the operator is signed in to this page in the
     * first place; offering it as the source to test issuance with would sign them out of it.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testDoesNotOfferTheAdminAuthenticationSource(): void
    {
        $this->authSourceIds = ['admin', self::AUTH_SOURCE_ID, 'second-sp'];

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame(
            [self::AUTH_SOURCE_ID, 'second-sp'],
            array_values((array)($this->templateData['authSourceIds'] ?? [])),
        );
    }


    /**
     * Clearing is what lets the page be used twice: the second run has to start from an unauthenticated
     * user, or it would issue against whoever the first run signed in.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testClearingSignsTheUserOutAndForgetsTheSelection(): void
    {
        $this->sessionData = [
            'auth_source_id' => self::AUTH_SOURCE_ID,
            'credential_configuration_id' => self::CONFIGURATION_ID,
        ];

        $this->authSimpleMock->expects($this->once())->method('logout');
        $this->sessionMock->expects($this->exactly(2))->method('deleteData');

        $response = $this->sut()->verifiableCredentialIssuance(
            $this->request(['clear' => '1'], Request::METHOD_POST),
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testClearingSignsNobodyOutWhenTheSessionIsAlreadyUnauthenticated(): void
    {
        $this->sessionData = ['auth_source_id' => self::AUTH_SOURCE_ID];
        $this->isAuthenticated = false;

        $this->authSimpleMock->expects($this->never())->method('logout');
        $this->sessionMock->expects($this->exactly(2))->method('deleteData');

        $this->sut()->verifiableCredentialIssuance($this->request(['clear' => '1'], Request::METHOD_POST));
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testClearingWithNoSelectedSourceStillForgetsTheSelection(): void
    {
        $this->authSimpleFactoryMock->expects($this->never())->method('forAuthSourceId');
        $this->sessionMock->expects($this->exactly(2))->method('deleteData');

        $this->sut()->verifiableCredentialIssuance($this->request(['clear' => '1'], Request::METHOD_POST));
    }


    /**
     * The pre-authorized flow issues against a user's attributes, so there has to be a user first. The
     * selection is put in the session because authenticating leaves this page and comes back to it.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testStartsAuthenticationForThePreAuthorizedFlowWhenNobodyIsSignedIn(): void
    {
        $this->isAuthenticated = false;
        $this->requestParams = [
            'authSourceId' => self::AUTH_SOURCE_ID,
            'credentialConfigurationId' => self::CONFIGURATION_ID,
            'grantType' => GrantTypesEnum::PreAuthorizedCode->value,
        ];

        $this->sessionMock->expects($this->exactly(2))->method('setData');
        $this->authSimpleMock->expects($this->once())->method('login')->with(['ReturnTo' => self::PAGE_URL]);

        $this->sut()->verifiableCredentialIssuance($this->request());
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testBuildsAPreAuthorizedOfferFromTheSignedInUsersAttributes(): void
    {
        $this->requestParams = [
            'authSourceId' => self::AUTH_SOURCE_ID,
            'credentialConfigurationId' => self::CONFIGURATION_ID,
            'grantType' => GrantTypesEnum::PreAuthorizedCode->value,
            'useTxCode' => '1',
            'usersEmailAttributeName' => 'emailAddress',
        ];

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], ['givenName' => ['John']], true, 'emailAddress')
            ->willReturn(self::OFFER_URI);
        $this->authSimpleMock->expects($this->never())->method('login');

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame(self::OFFER_URI, $this->templateData['credentialOfferUri'] ?? null);
    }


    /**
     * Which attribute holds the address is a property of the authentication source, so leaving the
     * field empty asks for the configured one rather than for none.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testFallsBackToTheConfiguredEmailAttributeWhenTheFieldIsBlank(): void
    {
        $this->requestParams = [
            'authSourceId' => self::AUTH_SOURCE_ID,
            'credentialConfigurationId' => self::CONFIGURATION_ID,
            'grantType' => GrantTypesEnum::PreAuthorizedCode->value,
            'usersEmailAttributeName' => '   ',
        ];

        $this->moduleConfigMock->expects($this->once())
            ->method('getUsersEmailAttributeNameForAuthSourceId')
            ->with(self::AUTH_SOURCE_ID)
            ->willReturn('mail');

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], $this->anything(), false, 'mail')
            ->willReturn(self::OFFER_URI);

        $this->sut()->verifiableCredentialIssuance($this->request());
    }


    /**
     * The authorization-code flow authenticates the holder later, at the issuer, so no authentication
     * source is needed here and none is started.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testBuildsAnAuthorizationCodeOfferWithoutAuthenticatingAnybody(): void
    {
        $this->requestParams = [
            'credentialConfigurationId' => self::CONFIGURATION_ID,
            'grantType' => GrantTypesEnum::AuthorizationCode->value,
        ];

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildForAuthorization')
            ->with([self::CONFIGURATION_ID])
            ->willReturn(self::OFFER_URI);
        $this->authSimpleMock->expects($this->never())->method('login');

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame(self::OFFER_URI, $this->templateData['credentialOfferUri'] ?? null);
    }


    /**
     * The offer is delivered by being scanned, so the page renders it as a QR code - with the URI
     * encoded, since it is being carried inside another one.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testRendersTheOfferAsAScannableCode(): void
    {
        $this->requestParams = [
            'credentialConfigurationId' => self::CONFIGURATION_ID,
            'grantType' => GrantTypesEnum::AuthorizationCode->value,
        ];

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame(
            'https://quickchart.io/qr?size=200&margin=1&text=' . urlencode(self::OFFER_URI),
            $this->templateData['credentialOfferQrUri'] ?? null,
        );
    }


    /**
     * Coming back from authentication, the page has to remember which credential was being tested: the
     * form which named it was left behind when the user was sent off to sign in.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testTakesTheSelectionFromTheSessionWhenTheRequestCarriesNone(): void
    {
        $this->sessionData = [
            'auth_source_id' => self::AUTH_SOURCE_ID,
            'credential_configuration_id' => self::CONFIGURATION_ID,
        ];
        $this->requestParams = ['grantType' => GrantTypesEnum::PreAuthorizedCode->value];

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], ['givenName' => ['John']], false, $this->anything())
            ->willReturn(self::OFFER_URI);

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertSame(
            self::CONFIGURATION_ID,
            $this->templateData['selectedCredentialConfigurationId'] ?? null,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testBuildsNoOfferWhenNoCredentialWasSelected(): void
    {
        $this->requestParams = ['grantType' => GrantTypesEnum::AuthorizationCode->value];

        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $this->sut()->verifiableCredentialIssuance($this->request());

        $this->assertArrayHasKey('credentialOfferUri', $this->templateData);
        $this->assertNull($this->templateData['credentialOfferUri']);
    }


    /**
     * The page it renders is the one the menu marks as current, which is what tells an administrator
     * where they are.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\OpenID\Exceptions\CredentialOfferException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    public function testRendersTheIssuanceTestPage(): void
    {
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->expects($this->once())
            ->method('build')
            ->with(
                'oidc:tests/verifiable-credential-issuance.twig',
                $this->anything(),
                RoutesEnum::AdminTestVerifiableCredentialIssuance->value,
            )
            ->willReturn($this->createMock(Template::class));

        $this->sut()->verifiableCredentialIssuance($this->request());
    }
}
