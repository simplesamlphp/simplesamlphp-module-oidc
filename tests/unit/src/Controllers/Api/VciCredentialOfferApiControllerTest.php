<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Api;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Controllers\Api\VciCredentialOfferApiController;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(VciCredentialOfferApiController::class)]
#[AllowMockObjectsWithoutExpectations]
class VciCredentialOfferApiControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'university_degree';

    protected const string OFFER_URI = 'openid-credential-offer://?credential_offer_uri=' .
    'https%3A%2F%2Fissuer.example.org%2Foffer%2Fabc';

    protected const string AUTH_SOURCE_ID = 'default-sp';


    protected MockObject $moduleConfigMock;

    protected MockObject $authorizationMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $routesMock;

    protected MockObject $credentialOfferUriFactoryMock;

    /** @var ?array<string,mixed> What the credential configuration ID resolves to. */
    protected ?array $credentialConfiguration = null;

    /** @var array<string,mixed> Body of the JSON response the controller produced. */
    protected array $responseData = [];


    protected function setUp(): void
    {
        $this->credentialConfiguration = ['format' => 'jwt_vc_json'];
        $this->responseData = [];

        $this->moduleConfigMock = $this->moduleConfigWith();
        // Read through the property rather than re-stubbed per test: a mock keeps the first matcher
        // registered for a method, so a second stub in a test body would silently never fire.
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturnCallback(fn(): ?array => $this->credentialConfiguration);

        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->credentialOfferUriFactoryMock = $this->createMock(CredentialOfferUriFactory::class);
        $this->credentialOfferUriFactoryMock->method('buildForAuthorization')->willReturn(self::OFFER_URI);
        $this->credentialOfferUriFactoryMock->method('buildPreAuthorized')->willReturn(self::OFFER_URI);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            function (array $data): JsonResponse {
                $this->responseData = $data;

                return new JsonResponse($data);
            },
        );
        $this->routesMock->method('newJsonErrorResponse')->willReturnCallback(
            static fn(
                string $error,
                string $description,
                int $httpCode = 500,
                array $headers = [],
            ): JsonResponse => new JsonResponse(
                ['error' => $error, 'error_description' => $description],
                $httpCode,
                $headers,
            ),
        );
    }


    protected function moduleConfigWith(
        bool $apiEnabled = true,
        bool $vciEnabled = true,
        bool $offerEndpointEnabled = true,
    ): MockObject {
        $moduleConfigMock = $this->createMock(ModuleConfig::class);
        $moduleConfigMock->method('getApiEnabled')->willReturn($apiEnabled);
        $moduleConfigMock->method('getVciEnabled')->willReturn($vciEnabled);
        $moduleConfigMock->method('getApiVciCredentialOfferEndpointEnabled')->willReturn($offerEndpointEnabled);

        return $moduleConfigMock;
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    protected function sut(): VciCredentialOfferApiController
    {
        return new VciCredentialOfferApiController(
            $this->moduleConfigMock,
            $this->authorizationMock,
            $this->loggerServiceMock,
            $this->routesMock,
            $this->credentialOfferUriFactoryMock,
        );
    }


    /**
     * @param array<string,mixed> $body
     */
    protected function request(array $body = []): Request
    {
        $body = $body === [] ? [
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::AuthorizationCode->value,
        ] : $body;

        $request = new Request([], [], [], [], [], [], (string)json_encode($body));
        $request->setMethod('POST');
        $request->headers->set('Content-Type', 'application/json');

        return $request;
    }


    /**
     * The API master switch is checked before anything else, so a deployment which never turned the API
     * on has no offer endpoint at all rather than one which merely refuses callers.
     */
    public function testRefusesWhenTheApiIsNotEnabled(): void
    {
        $this->moduleConfigMock = $this->moduleConfigWith(apiEnabled: false);

        $this->expectException(OidcServerException::class);

        $this->sut();
    }


    /**
     * Verifiable Credentials have a master switch of their own, and this endpoint belongs to it as much
     * as to the API.
     */
    public function testRefusesWhenVerifiableCredentialsAreNotEnabled(): void
    {
        $this->moduleConfigMock = $this->moduleConfigWith(vciEnabled: false);

        $this->expectException(OidcServerException::class);

        $this->sut();
    }


    /**
     * And the per-endpoint switch, which is what lets a deployment run the rest of the API without
     * handing out credential offers.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesWhenTheCredentialOfferEndpointIsNotEnabled(): void
    {
        $this->moduleConfigMock = $this->moduleConfigWith(offerEndpointEnabled: false);

        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');

        $this->expectException(OidcServerException::class);

        $this->sut()->credentialOffer($this->request());
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRequiresATokenCarryingACredentialOfferScope(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->expects($this->once())
            ->method('requireTokenForAnyOfScope')
            ->with(
                $this->anything(),
                [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            );
        $this->authorizationMock = $authorization;

        $this->sut()->credentialOffer($this->request());
    }


    /**
     * An offer is a credential waiting to be collected, so an unauthorized request must not cause one
     * to be built - not merely fail to return it.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesAnUnauthorizedRequestWithoutBuildingAnOffer(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireTokenForAnyOfScope')
            ->willThrowException(new AuthorizationException('Authorization token not provided.'));
        $this->authorizationMock = $authorization;

        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $this->assertSame(
            Response::HTTP_UNAUTHORIZED,
            $this->sut()->credentialOffer($this->request())->getStatusCode(),
        );
    }


    /**
     * The description is asserted as well as the status, because these refusals share a status code and
     * differ only in what they say. Without it, a request refused for the wrong reason still looks
     * refused - and a grant type which stopped being checked would fall through to the "no
     * implementation" answer at the end and go unnoticed.
     *
     * @param array<string,mixed> $body
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('unusableRequestBodyProvider')]
    public function testRefusesARequestItCanNotBuildAnOfferFrom(array $body, string $expectedDescription): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $response = $this->sut()->credentialOffer($this->request($body));

        $this->assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());

        /** @var array<string,mixed> $payload */
        $payload = json_decode((string)$response->getContent(), true);

        $this->assertSame('invalid_request', $payload['error'] ?? null);
        $this->assertStringContainsString(
            $expectedDescription,
            (string)($payload['error_description'] ?? ''),
        );
    }


    /**
     * @return array<string,array{0: array<string,mixed>, 1: string}>
     */
    public static function unusableRequestBodyProvider(): array
    {
        return [
            'no credential configuration ID' => [
                ['grant_type' => GrantTypesEnum::AuthorizationCode->value],
                'No credential configuration ID',
            ],
            'credential configuration ID is not a string' => [
                [
                    'credential_configuration_id' => ['an', 'array'],
                    'grant_type' => GrantTypesEnum::AuthorizationCode->value,
                ],
                'No credential configuration ID',
            ],
            'no grant type' => [
                ['credential_configuration_id' => self::CONFIGURATION_ID],
                'No credential Grant Type',
            ],
            'grant type is not a string' => [
                ['credential_configuration_id' => self::CONFIGURATION_ID, 'grant_type' => 42],
                'No credential Grant Type',
            ],
            'grant type is not one this server knows' => [
                ['credential_configuration_id' => self::CONFIGURATION_ID, 'grant_type' => 'made_up'],
                'Invalid credential Grant Type',
            ],
            'implicit grant, which can not issue credentials' => [
                [
                    'credential_configuration_id' => self::CONFIGURATION_ID,
                    'grant_type' => GrantTypesEnum::Implicit->value,
                ],
                'can not be used for verifiable credential issuance',
            ],
            'refresh token grant, which can not issue credentials' => [
                [
                    'credential_configuration_id' => self::CONFIGURATION_ID,
                    'grant_type' => GrantTypesEnum::RefreshToken->value,
                ],
                'can not be used for verifiable credential issuance',
            ],
        ];
    }


    /**
     * A configuration this issuer does not offer is refused here rather than at collection time, so the
     * caller learns about it while it can still fix the request.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesAnUnsupportedCredentialConfigurationId(): void
    {
        $this->credentialConfiguration = null;

        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');

        $this->assertSame(
            Response::HTTP_BAD_REQUEST,
            $this->sut()->credentialOffer($this->request())->getStatusCode(),
        );
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testBuildsAnOfferForTheAuthorizationCodeFlow(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildForAuthorization')
            ->with([self::CONFIGURATION_ID])
            ->willReturn(self::OFFER_URI);
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $response = $this->sut()->credentialOffer($this->request());

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(self::OFFER_URI, $this->responseData['credential_offer_uri'] ?? null);
    }


    /**
     * The pre-authorized flow carries everything the credential will be built from in the offer itself,
     * so what the request asked for has to reach the factory unchanged.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testBuildsAnOfferForThePreAuthorizedCodeFlow(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with(
                [self::CONFIGURATION_ID],
                ['givenName' => ['John']],
                true,
                'mail',
            )
            ->willReturn(self::OFFER_URI);
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'user_attributes' => ['givenName' => ['John']],
            'use_tx_code' => true,
            'users_email_attribute_name' => 'mail',
        ]));

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(self::OFFER_URI, $this->responseData['credential_offer_uri'] ?? null);
    }


    /**
     * A transaction code has to be asked for. Sending one by default would mean every offer needed a
     * second channel to deliver it over.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testDoesNotUseATransactionCodeUnlessTheRequestAsksFor(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, null)
            ->willReturn(self::OFFER_URI);

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
        ]));
    }


    /**
     * Which attribute holds the user's address is a property of the authentication source, so a caller
     * which names the source need not know the attribute as well.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testResolvesTheEmailAttributeFromTheAuthenticationSourceWhenTheRequestNamesNone(): void
    {
        $this->moduleConfigMock->expects($this->once())
            ->method('getUsersEmailAttributeNameForAuthSourceId')
            ->with(self::AUTH_SOURCE_ID)
            ->willReturn('mail');

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, 'mail')
            ->willReturn(self::OFFER_URI);

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'authentication_source_id' => self::AUTH_SOURCE_ID,
        ]));
    }


    /**
     * An attribute name in the request is what the caller meant, so the authentication source is not
     * consulted to overrule it.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testPrefersTheEmailAttributeTheRequestNamed(): void
    {
        $this->moduleConfigMock->expects($this->never())->method('getUsersEmailAttributeNameForAuthSourceId');

        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, 'emailAddress')
            ->willReturn(self::OFFER_URI);

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'authentication_source_id' => self::AUTH_SOURCE_ID,
            'users_email_attribute_name' => 'emailAddress',
        ]));
    }


    /**
     * The attributes end up in a credential, so a value which is not a set of them contributes none
     * rather than being passed on for something further down to choke on.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testIgnoresUserAttributesWhichAreNotASetOfThem(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, null)
            ->willReturn(self::OFFER_URI);

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'user_attributes' => 'not a set of attributes',
        ]));
    }
}
