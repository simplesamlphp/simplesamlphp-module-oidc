<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Api;

use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Codebooks\ApiScopesEnum;
use SimpleSAML\Module\oidc\Controllers\Api\VciCredentialOfferApiController;
use SimpleSAML\Module\oidc\Exceptions\AuthorizationException;
use SimpleSAML\Module\oidc\Exceptions\InsufficientScopeException;
use SimpleSAML\Module\oidc\Exceptions\MissingTokenException;
use SimpleSAML\Module\oidc\Factories\CredentialOfferUriFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\CredentialOfferRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\Api\Authorization;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryPosition;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\ValueAbstracts\ApiCaller;
use SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\BuiltCredentialOffer;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

#[CoversClass(VciCredentialOfferApiController::class)]
#[AllowMockObjectsWithoutExpectations]
class VciCredentialOfferApiControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'university_degree';

    protected const string OFFER_URI = 'openid-credential-offer://?credential_offer_uri=' .
    'https%3A%2F%2Fissuer.example.org%2Foffer%2Fabc';

    protected const string OFFER_ID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';

    protected const string AUTH_SOURCE_ID = 'default-sp';


    protected MockObject $moduleConfigMock;

    protected MockObject $authorizationMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $routesMock;

    protected MockObject $credentialOfferUriFactoryMock;

    protected MockObject $credentialOfferRepositoryMock;

    protected MockObject $statusListEntryRepositoryMock;

    /** @var ?array<string,mixed> What the credential configuration ID resolves to. */
    protected ?array $credentialConfiguration = null;

    /** Which credential configurations the authorized caller may offer. */
    protected CredentialConfigurationLimit $credentialConfigurationLimit;

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

        // Read through the property, as the credential configuration is: a caller limited to the configuration
        // offered, so that a test about something else is not refused for it.
        $this->credentialConfigurationLimit = CredentialConfigurationLimit::to([self::CONFIGURATION_ID]);
        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->authorizationMock->method('requireAdminOrTokenForAnyOfScope')
            ->willReturnCallback(fn(): ApiCaller => new ApiCaller('HR system', $this->credentialConfigurationLimit));
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->credentialOfferUriFactoryMock = $this->createMock(CredentialOfferUriFactory::class);
        $this->credentialOfferUriFactoryMock->method('buildForAuthorization')->willReturn($this->builtOffer());
        $this->credentialOfferUriFactoryMock->method('buildPreAuthorized')->willReturn($this->builtOffer());

        $this->credentialOfferRepositoryMock = $this->createMock(CredentialOfferRepository::class);
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);

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
            $this->credentialOfferRepositoryMock,
            $this->statusListEntryRepositoryMock,
        );
    }


    protected function builtOffer(): BuiltCredentialOffer
    {
        return new BuiltCredentialOffer(self::OFFER_URI, self::OFFER_ID);
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
            ->method('requireAdminOrTokenForAnyOfScope')
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
        $authorization->method('requireAdminOrTokenForAnyOfScope')
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
            ->willReturn($this->builtOffer());
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $response = $this->sut()->credentialOffer($this->request());

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(self::OFFER_URI, $this->responseData['credential_offer_uri'] ?? null);
        $this->assertSame(self::OFFER_ID, $this->responseData['offer_id'] ?? null);
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
            ->willReturn($this->builtOffer());
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
        $this->assertSame(self::OFFER_ID, $this->responseData['offer_id'] ?? null);
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
            ->willReturn($this->builtOffer());

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
            ->willReturn($this->builtOffer());

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
            ->willReturn($this->builtOffer());

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
    /**
     * The transaction code is mailed to the user, so user attributes holding no email address can not carry
     * one. That is the caller's mistake, answered as one, and nothing is built or stored for it.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRefusesATransactionCodeWithoutAnEmailAddressToSendItTo(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('getUserEmail')
            ->with('mail', ['givenName' => ['John']])
            ->willThrowException(new RuntimeException("Could not extract user email: No such attribute 'mail'."));
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'user_attributes' => ['givenName' => ['John']],
            'use_tx_code' => true,
            'users_email_attribute_name' => 'mail',
        ]));

        $this->assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->jsonOf($response)['error'] ?? null);
    }


    /**
     * Named by neither the request nor its authentication source, the address is looked for where the
     * factory will look for it: under the default email attribute.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testLooksForTheEmailAddressUnderTheDefaultAttributeWhenNothingNamesAnother(): void
    {
        $this->moduleConfigMock->method('getDefaultUsersEmailAttributeName')->willReturn('defaultMail');
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('getUserEmail')
            ->with('defaultMail', ['defaultMail' => ['user@example.org']])
            ->willReturn('user@example.org');
        $this->credentialOfferUriFactoryMock->expects($this->once())->method('buildPreAuthorized');

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'user_attributes' => ['defaultMail' => ['user@example.org']],
            'use_tx_code' => true,
        ]));

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
    }


    /**
     * Without a transaction code nothing is mailed, so no address is needed.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testNeedsNoEmailAddressWithoutATransactionCode(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('getUserEmail');

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
        ]));

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
    }


    /**
     * A failure to build the offer -- storage, or the mail carrying a transaction code -- is this server's,
     * and is answered as a JSON error like every other answer of this API, not left to reach SimpleSAMLphp's
     * HTML error page. What went wrong goes to the log, not to the caller.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('grantTypeProvider')]
    public function testAnswersAFailureToBuildTheOfferAsAJsonServerError(string $grantType): void
    {
        // A fresh double: the one from setUp() already answers both builds, and a mock keeps its first stub.
        $this->credentialOfferUriFactoryMock = $this->createMock(CredentialOfferUriFactory::class);
        $failure = new RuntimeException('technicalcontact_email must be changed from the default value');
        $this->credentialOfferUriFactoryMock->method('buildForAuthorization')->willThrowException($failure);
        $this->credentialOfferUriFactoryMock->method('buildPreAuthorized')->willThrowException($failure);
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with($this->stringContains('technicalcontact_email must be changed from the default value'));

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => $grantType,
        ]));

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertSame(
            ['error' => 'server_error', 'error_description' => 'Credential Offer could not be built.'],
            $this->jsonOf($response),
        );
    }


    /**
     * @return array<string,array{string}>
     */
    public static function grantTypeProvider(): array
    {
        return [
            'authorization code' => [GrantTypesEnum::AuthorizationCode->value],
            'pre-authorized code' => [GrantTypesEnum::PreAuthorizedCode->value],
        ];
    }


    /**
     * @return array<string,mixed>
     */
    protected function jsonOf(Response $response): array
    {
        $data = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($data);

        return $data;
    }


    /**
     * A caller which may offer the configuration asked for gets its offer, whichever grant it asks for, and
     * whatever else it may offer beside it. An administrator's session, which is not limited, likewise.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('permittedOfferProvider')]
    public function testOffersACredentialConfigurationTheCallerMayOffer(
        string $grantType,
        CredentialConfigurationLimit $credentialConfigurationLimit,
    ): void {
        $this->credentialConfigurationLimit = $credentialConfigurationLimit;

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => $grantType,
        ]));

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $this->assertSame(self::OFFER_URI, $this->responseData['credential_offer_uri'] ?? null);
        $this->assertSame(self::OFFER_ID, $this->responseData['offer_id'] ?? null);
    }


    /**
     * @return array<string,array{string, \SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit}>
     */
    public static function permittedOfferProvider(): array
    {
        $cases = [];

        foreach (self::grantTypeProvider() as $grant => [$grantType]) {
            $cases[$grant . ', the one configuration'] = [
                $grantType,
                CredentialConfigurationLimit::to([self::CONFIGURATION_ID]),
            ];
            $cases[$grant . ', among others'] = [
                $grantType,
                CredentialConfigurationLimit::to(['employee_card', self::CONFIGURATION_ID, 'library_card']),
            ];
            $cases[$grant . ', no limit'] = [$grantType, CredentialConfigurationLimit::unlimited()];
        }

        return $cases;
    }


    /**
     * A configuration the caller may not offer is refused as a token which does not cover the request, for
     * either grant: an authorization code offer carries no attributes, but which credentials a token may
     * advertise to wallets is still the token's limit. Nothing is built, so nothing is stored or mailed.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('refusedOfferProvider')]
    public function testRefusesACredentialConfigurationTheCallerMayNotOffer(
        string $grantType,
        CredentialConfigurationLimit $credentialConfigurationLimit,
    ): void {
        $this->credentialConfigurationLimit = $credentialConfigurationLimit;
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildPreAuthorized');
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('getUserEmail');

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => $grantType,
            'user_attributes' => ['mail' => ['jdoe@example.org']],
            'use_tx_code' => true,
        ]));

        $this->assertSame(Response::HTTP_FORBIDDEN, $response->getStatusCode());
        $this->assertSame(
            [
                'error' => 'insufficient_scope',
                'error_description' => 'The API token may not offer this credential configuration.',
            ],
            $this->jsonOf($response),
        );
        $this->assertSame(
            'Bearer error="insufficient_scope"',
            $response->headers->get(VciCredentialOfferApiController::HEADER_WWW_AUTHENTICATE),
        );
    }


    /**
     * @return array<string,array{string, \SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit}>
     */
    public static function refusedOfferProvider(): array
    {
        $cases = [];

        foreach (self::grantTypeProvider() as $grant => [$grantType]) {
            $cases[$grant . ', others only'] = [
                $grantType,
                CredentialConfigurationLimit::to(['employee_card', 'library_card']),
            ];
            // A configuration whose ID merely starts with the one offered.
            $cases[$grant . ', a longer ID'] = [
                $grantType,
                CredentialConfigurationLimit::to([self::CONFIGURATION_ID . '_v2']),
            ];
            $cases[$grant . ', none at all'] = [$grantType, CredentialConfigurationLimit::to([])];
        }

        return $cases;
    }


    /**
     * A configuration which does not exist is answered as one, whatever the caller may offer: the limit
     * comes after it, and tells the caller nothing the published metadata does not.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAnswersAnUnknownCredentialConfigurationAsUnknownWhateverTheCallerMayOffer(): void
    {
        $this->credentialConfiguration = null;
        $this->credentialConfigurationLimit = CredentialConfigurationLimit::to([]);

        $response = $this->sut()->credentialOffer($this->request());

        $this->assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->jsonOf($response)['error'] ?? null);
    }


    /**
     * A token whose credential configurations can not be read is this server's fault: answered as a JSON
     * server error, with the cause in the log, and no offer built.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAnswersAnUnreadableTokenConfigurationAsAJsonServerError(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireAdminOrTokenForAnyOfScope')
            ->willThrowException(new ConfigurationError('credential_configuration_ids must be a list'));
        $this->authorizationMock = $authorization;
        $this->credentialOfferUriFactoryMock->expects($this->never())->method('buildForAuthorization');
        $this->loggerServiceMock->expects($this->once())->method('error')
            ->with($this->stringContains('credential_configuration_ids must be a list'));

        $response = $this->sut()->credentialOffer($this->request());

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertSame(
            ['error' => 'server_error', 'error_description' => 'Authorization could not be resolved.'],
            $this->jsonOf($response),
        );
    }


    public function testIgnoresUserAttributesWhichAreNotASetOfThem(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, null)
            ->willReturn($this->builtOffer());

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
            'user_attributes' => 'not a set of attributes',
        ]));
    }


    /**
     * The offer records who made it, so that only that caller can ask what it produced: a pre-authorized offer
     * made through a token carries the principal the token stands for to the factory.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRecordsTheTokenCallerAsTheOwnerOfAPreAuthorizedOffer(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildPreAuthorized')
            ->with([self::CONFIGURATION_ID], [], false, null, 'HR system')
            ->willReturn($this->builtOffer());

        $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'grant_type' => GrantTypesEnum::PreAuthorizedCode->value,
        ]));
    }


    /**
     * Likewise for an authorization code offer, whose owner is the second argument of its factory method.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRecordsTheTokenCallerAsTheOwnerOfAnAuthorizationCodeOffer(): void
    {
        $this->credentialOfferUriFactoryMock->expects($this->once())
            ->method('buildForAuthorization')
            ->with([self::CONFIGURATION_ID], 'HR system')
            ->willReturn($this->builtOffer());

        $this->sut()->credentialOffer($this->request());
    }


    /**
     * An administrator's session owns no offer, which is how an offer of the administration screens is told from
     * an API caller's, and it is not limited in what it may offer.
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('grantTypeProvider')]
    public function testRecordsNoOwnerForAnAdministratorAndOffersAnyConfiguration(string $grantType): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireAdminOrTokenForAnyOfScope')->willReturn(null);
        $this->authorizationMock = $authorization;

        $this->credentialOfferUriFactoryMock->expects($this->exactly(
            $grantType === GrantTypesEnum::AuthorizationCode->value ? 1 : 0,
        ))
            ->method('buildForAuthorization')
            ->with(['library_card'], null)
            ->willReturn($this->builtOffer());
        $this->credentialOfferUriFactoryMock->expects($this->exactly(
            $grantType === GrantTypesEnum::PreAuthorizedCode->value ? 1 : 0,
        ))
            ->method('buildPreAuthorized')
            ->with(['library_card'], [], false, null, null)
            ->willReturn($this->builtOffer());

        $response = $this->sut()->credentialOffer($this->request([
            'credential_configuration_id' => 'library_card',
            'grant_type' => $grantType,
        ]));

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
    }


    protected function employeeCaller(): ApiCaller
    {
        return new ApiCaller('HR system', CredentialConfigurationLimit::to(['employee_card']));
    }


    protected function authorizeDetailsAs(ApiCaller $caller): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')->willReturn($caller);
        $this->authorizationMock = $authorization;
    }


    /**
     * @param list<string> $configurationIds
     */
    protected function offerRecord(
        ?string $owner = 'HR system',
        array $configurationIds = ['employee_card'],
        ?DateTimeImmutable $redeemedAt = null,
        ?DateTimeImmutable $withdrawnAt = null,
    ): CredentialOfferRecord {
        return new CredentialOfferRecord(
            self::OFFER_ID,
            $owner,
            $configurationIds,
            GrantTypesEnum::PreAuthorizedCode->value,
            new DateTimeImmutable('2026-11-01 10:00:00', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-11-01 11:00:00', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-11-02 11:00:00', new DateTimeZone('UTC')),
            $redeemedAt,
            $withdrawnAt,
        );
    }


    protected function credentialEntry(
        int $idx,
        int $status = 0,
        ?DateTimeImmutable $expiresAt = null,
    ): StatusListEntryRecord {
        $issuedAt = (new DateTimeImmutable('2026-11-01 10:00:00', new DateTimeZone('UTC')))
            ->modify(sprintf('+%d seconds', $idx));

        return new StatusListEntryRecord(
            'list-1',
            $idx,
            true,
            $status,
            $expiresAt,
            'https://issuer.example.org/vc/' . $idx,
            'hash-' . $idx,
            'employee_card',
            null,
            $issuedAt,
            $issuedAt,
            self::OFFER_ID,
        );
    }


    /**
     * @param array<string,mixed> $query
     */
    protected function detailsRequest(array $query = []): Request
    {
        return new Request($query);
    }


    /**
     * The per-endpoint switch is checked first, so a deployment with the offer endpoint off has no listing either,
     * and nobody is asked to authorize for it.
     */
    public function testRefusesTheListingWhenTheCredentialOfferEndpointIsNotEnabled(): void
    {
        $this->moduleConfigMock = $this->moduleConfigWith(offerEndpointEnabled: false);
        $authorization = $this->createMock(Authorization::class);
        $authorization->expects($this->never())->method('requireBearerTokenForAnyOfScope');
        $this->authorizationMock = $authorization;

        $this->expectException(OidcServerException::class);

        $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);
    }


    /**
     * Every way authorization can fail is answered before anything about the offer is read, with the challenge
     * RFC 6750 asks for: a request which carried no token gets the bare one, a token which did arrive and was not
     * accepted `invalid_token`, a token without the scope its scope, and a configuration this server can not
     * read no challenge at all.
     *
     * @param \Throwable $failure
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('authorizationFailureProvider')]
    public function testAnswersAuthorizationFailuresBeforeReadingAnything(
        Throwable $failure,
        int $expectedStatus,
        string $expectedError,
        ?string $expectedChallenge,
    ): void {
        $authorization = $this->createMock(Authorization::class);
        $authorization->method('requireBearerTokenForAnyOfScope')->willThrowException($failure);
        $this->authorizationMock = $authorization;
        $this->credentialOfferRepositoryMock->expects($this->never())->method('find');
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $response = $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);

        $this->assertSame($expectedStatus, $response->getStatusCode());
        $this->assertSame($expectedError, $this->jsonOf($response)['error'] ?? null);
        $this->assertSame(
            $expectedChallenge,
            $response->headers->get(VciCredentialOfferApiController::HEADER_WWW_AUTHENTICATE),
        );
    }


    /**
     * @return array<string,array{\Throwable, int, string, ?string}>
     */
    public static function authorizationFailureProvider(): array
    {
        return [
            'no token' => [
                new MissingTokenException('Authorization token not provided.'),
                Response::HTTP_UNAUTHORIZED,
                'unauthorized',
                'Bearer',
            ],
            'a token which is not accepted' => [
                new AuthorizationException('Token is not valid.'),
                Response::HTTP_UNAUTHORIZED,
                'unauthorized',
                'Bearer error="invalid_token"',
            ],
            'a token without the scope' => [
                new InsufficientScopeException('Token lacks the scope.'),
                Response::HTTP_FORBIDDEN,
                'insufficient_scope',
                'Bearer error="insufficient_scope", scope="vci_credential_offer"',
            ],
            'an unreadable token configuration' => [
                new ConfigurationError('credential_configuration_ids must be a list'),
                Response::HTTP_INTERNAL_SERVER_ERROR,
                'server_error',
                null,
            ],
        ];
    }


    /**
     * The listing takes a bearer token with one of the scopes of the offer endpoint, or the broader ones, and
     * nothing else.
     */
    public function testRequiresATokenCarryingACredentialOfferScopeForTheListing(): void
    {
        $authorization = $this->createMock(Authorization::class);
        $authorization->expects($this->once())
            ->method('requireBearerTokenForAnyOfScope')
            ->with(
                $this->anything(),
                [ApiScopesEnum::VciCredentialOffer, ApiScopesEnum::VciAll, ApiScopesEnum::All],
            )
            ->willReturn($this->employeeCaller());
        $this->authorizationMock = $authorization;

        $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);
    }


    /**
     * An offer id of any form which is not exactly 64 lower-case hex characters is answered as not found without
     * a lookup, so that a database ignoring case or trailing characters never finds an offer under a spelling it
     * was not given as.
     */
    #[DataProvider('malformedOfferIdProvider')]
    public function testAnswersAMalformedOfferIdAsNotFoundWithoutALookup(string $offerId): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->expects($this->never())->method('find');
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $this->assertNotFound($this->sut()->credentialOfferDetails($this->detailsRequest(), $offerId));
    }


    /**
     * @return array<string,array{string}>
     */
    public static function malformedOfferIdProvider(): array
    {
        return [
            'upper-case hex' => [strtoupper(self::OFFER_ID)],
            '63 hex characters' => [substr(self::OFFER_ID, 0, 63)],
            '65 hex characters' => [self::OFFER_ID . '0'],
            'not hex' => [str_repeat('g', 64)],
            'trailing newline' => [self::OFFER_ID . "\n"],
            'empty' => [''],
        ];
    }


    protected function assertNotFound(Response $response): void
    {
        $this->assertSame(Response::HTTP_NOT_FOUND, $response->getStatusCode());
        $this->assertSame(
            [
                'error' => 'not_found',
                'error_description' => 'No credential offer with that identifier can be shown.',
            ],
            $this->jsonOf($response),
        );
    }


    /**
     * Whatever the reason an offer is not the caller's to see, the answer is the same one and the credentials of
     * the offer are never read, so that no caller learns which offer ids exist or whose they are: unknown,
     * an administrator's, another caller's (compared byte for byte), or outside the token's list.
     */
    #[DataProvider('unseeableOfferProvider')]
    public function testAnswersAnOfferTheCallerMayNotSeeAsNotFound(
        ?CredentialOfferRecord $offer,
        CredentialConfigurationLimit $limit,
    ): void {
        $this->authorizeDetailsAs(new ApiCaller('HR system', $limit));
        $this->credentialOfferRepositoryMock->expects($this->once())
            ->method('find')
            ->with(self::OFFER_ID)
            ->willReturn($offer);
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $this->assertNotFound($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));
    }


    /**
     * @return array<string,array{
     *     ?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\CredentialOfferRecord,
     *     \SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit,
     * }>
     */
    public static function unseeableOfferProvider(): array
    {
        $employee = CredentialConfigurationLimit::to(['employee_card']);
        $offer = static fn(?string $owner, array $ids = ['employee_card']): CredentialOfferRecord =>
        new CredentialOfferRecord(
            self::OFFER_ID,
            $owner,
            $ids,
            GrantTypesEnum::PreAuthorizedCode->value,
            new DateTimeImmutable('2026-11-01 10:00:00', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-11-01 11:00:00', new DateTimeZone('UTC')),
            new DateTimeImmutable('2026-11-02 11:00:00', new DateTimeZone('UTC')),
        );

        return [
            'unknown' => [null, $employee],
            'an administrator\'s offer' => [$offer(null), $employee],
            'another caller\'s offer' => [$offer('Library system'), $employee],
            'an owner differing in case' => [$offer('hr system'), $employee],
            'an owner differing by a trailing space' => [$offer('HR system '), $employee],
            'a configuration outside the limit' => [
                $offer('HR system'),
                CredentialConfigurationLimit::to(['library_card']),
            ],
            'one of two configurations outside the limit' => [
                $offer('HR system', ['employee_card', 'library_card']),
                $employee,
            ],
        ];
    }


    /**
     * The caller's own offer, as far as its token's list still allows, is shown as recorded with the credentials
     * issued from it described the way the status API names them, and nothing else: no cursor for a single page.
     */
    #[DataProvider('seeingLimitProvider')]
    public function testShowsTheOfferOfTheCallerWithItsCredentials(CredentialConfigurationLimit $limit): void
    {
        $this->authorizeDetailsAs(new ApiCaller('HR system', $limit));
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord(
            redeemedAt: new DateTimeImmutable('2026-11-01 10:30:00', new DateTimeZone('UTC')),
        ));
        $expiresAt = new DateTimeImmutable('2026-12-01 10:00:00', new DateTimeZone('UTC'));
        $this->statusListEntryRepositoryMock->expects($this->once())
            ->method('findLinkedToOffer')
            ->with(self::OFFER_ID, 501, null)
            ->willReturn([
                $this->credentialEntry(0, 0, $expiresAt),
                $this->credentialEntry(1, 1),
                $this->credentialEntry(2, 2),
                $this->credentialEntry(3, 3),
            ]);

        $response = $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);

        $this->assertSame(Response::HTTP_OK, $response->getStatusCode());
        $data = $this->jsonOf($response);
        $this->assertSame(
            [
                'offer_id',
                'credential_configuration_ids',
                'grant_type',
                'created_at',
                'redeemable_until',
                'redeemed_at',
                'withdrawn_at',
                'credentials',
            ],
            array_keys($data),
        );
        $this->assertSame(self::OFFER_ID, $data['offer_id']);
        $this->assertSame(['employee_card'], $data['credential_configuration_ids']);
        $this->assertSame(GrantTypesEnum::PreAuthorizedCode->value, $data['grant_type']);
        $this->assertSame(
            (new DateTimeImmutable('2026-11-01 10:00:00', new DateTimeZone('UTC')))->getTimestamp(),
            $data['created_at'],
        );
        $this->assertSame(
            (new DateTimeImmutable('2026-11-01 11:00:00', new DateTimeZone('UTC')))->getTimestamp(),
            $data['redeemable_until'],
        );
        $this->assertSame(
            (new DateTimeImmutable('2026-11-01 10:30:00', new DateTimeZone('UTC')))->getTimestamp(),
            $data['redeemed_at'],
        );
        $this->assertNull($data['withdrawn_at']);

        $issuedAt = (new DateTimeImmutable('2026-11-01 10:00:00', new DateTimeZone('UTC')))->getTimestamp();
        $this->assertSame(
            [
                [
                    'credential_id' => 'https://issuer.example.org/vc/0',
                    'credential_configuration_id' => 'employee_card',
                    'status' => 'valid',
                    'issued_at' => $issuedAt,
                    'expires_at' => $expiresAt->getTimestamp(),
                ],
                [
                    'credential_id' => 'https://issuer.example.org/vc/1',
                    'credential_configuration_id' => 'employee_card',
                    'status' => 'invalid',
                    'issued_at' => $issuedAt + 1,
                    'expires_at' => null,
                ],
                [
                    'credential_id' => 'https://issuer.example.org/vc/2',
                    'credential_configuration_id' => 'employee_card',
                    'status' => 'suspended',
                    'issued_at' => $issuedAt + 2,
                    'expires_at' => null,
                ],
                [
                    'credential_id' => 'https://issuer.example.org/vc/3',
                    'credential_configuration_id' => 'employee_card',
                    'status' => 3,
                    'issued_at' => $issuedAt + 3,
                    'expires_at' => null,
                ],
            ],
            $data['credentials'],
        );
    }


    /**
     * @return array<string,array{\SimpleSAML\Module\oidc\ValueAbstracts\CredentialConfigurationLimit}>
     */
    public static function seeingLimitProvider(): array
    {
        return [
            'limited to the configuration' => [CredentialConfigurationLimit::to(['employee_card'])],
            'limited to several including it' => [
                CredentialConfigurationLimit::to(['library_card', 'employee_card']),
            ],
            'unlimited' => [CredentialConfigurationLimit::fromConfiguredIds(['*'])],
        ];
    }


    /**
     * The withdrawal moment of an offer is told as a timestamp as well, so a caller can tell a withdrawn offer
     * from one nobody collected.
     */
    public function testTellsWhenTheOfferWasWithdrawn(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $withdrawnAt = new DateTimeImmutable('2026-11-01 10:45:00', new DateTimeZone('UTC'));
        $this->credentialOfferRepositoryMock->method('find')
            ->willReturn($this->offerRecord(withdrawnAt: $withdrawnAt));
        $this->statusListEntryRepositoryMock->method('findLinkedToOffer')->willReturn([]);

        $data = $this->jsonOf($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));

        $this->assertNull($data['redeemed_at']);
        $this->assertSame($withdrawnAt->getTimestamp(), $data['withdrawn_at']);
        $this->assertSame([], $data['credentials']);
    }


    /**
     * @return list<\SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord>
     */
    protected function credentialEntries(int $count): array
    {
        $entries = [];

        for ($idx = 0; $idx < $count; $idx++) {
            $entries[] = $this->credentialEntry($idx);
        }

        return $entries;
    }


    /**
     * One credential more than a page is read to know there is another page without counting: the answer lists a
     * page, names where the next starts, and asking with that cursor starts the read right after the last
     * credential listed, by its issuance moment (UTC, to the second), list and index.
     */
    public function testPagesThroughTheCredentialsOfAnOffer(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord());

        $records = $this->credentialEntries(501);
        $calls = [];
        $this->statusListEntryRepositoryMock->method('findLinkedToOffer')->willReturnCallback(
            function (string $offerId, int $limit, ?StatusListEntryPosition $after) use (&$calls, $records): array {
                $calls[] = [$offerId, $limit, $after];

                return $after === null ? $records : [];
            },
        );

        $first = $this->jsonOf($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));

        $this->assertCount(500, $first['credentials']);
        $this->assertIsString($first['next_cursor'] ?? null);

        $this->sut()->credentialOfferDetails(
            $this->detailsRequest(['cursor' => $first['next_cursor']]),
            self::OFFER_ID,
        );

        $this->assertCount(2, $calls);
        $this->assertSame(501, $calls[1][1]);
        /** @var \SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryPosition $position */
        $position = $calls[1][2];
        $this->assertInstanceOf(StatusListEntryPosition::class, $position);
        $this->assertSame('UTC', $position->getIssuedAt()->getTimezone()->getName());
        $this->assertSame('2026-11-01 10:08:19', $position->getIssuedAt()->format('Y-m-d H:i:s'));
        $this->assertSame('list-1', $position->getStatusListId());
        $this->assertSame(499, $position->getIdx());
    }


    /**
     * A page which is exactly full, and no more, has no next page to point to.
     */
    public function testNamesNoNextPageForAnExactlyFullPage(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord());
        $this->statusListEntryRepositoryMock->method('findLinkedToOffer')
            ->willReturn($this->credentialEntries(500));

        $data = $this->jsonOf($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));

        $this->assertCount(500, $data['credentials']);
        $this->assertArrayNotHasKey('next_cursor', $data);
    }


    /**
     * A cursor is only ever one this endpoint wrote, so any other form is the caller's mistake and is refused
     * before the credentials are read, rather than interpreted.
     *
     * @param array<string,mixed> $query
     */
    #[DataProvider('malformedCursorProvider')]
    public function testRefusesAMalformedCursorWithoutReadingCredentials(array $query): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord());
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $response = $this->sut()->credentialOfferDetails($this->detailsRequest($query), self::OFFER_ID);

        $this->assertSame(Response::HTTP_BAD_REQUEST, $response->getStatusCode());
        $this->assertSame('invalid_request', $this->jsonOf($response)['error'] ?? null);
    }


    protected static function cursorOf(string $payload): string
    {
        return rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function malformedCursorProvider(): array
    {
        return [
            'not base64url' => [['cursor' => 'a+b']],
            'base64 of something which is not JSON' => [['cursor' => self::cursorOf('not json')]],
            'JSON which is not a list of three' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","list"]')]],
            'JSON object' => [['cursor' => self::cursorOf('{"a":"2026-11-11 10:00:00","b":"list","c":5}')]],
            'wrong types' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","list","5"]')]],
            'negative index' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","list",-1]')]],
            'empty list id' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","",5]')]],
            'a moment in another format' => [['cursor' => self::cursorOf('["2026-11-11T10:00:00Z","list",5]')]],
            'a moment which does not round-trip' => [['cursor' => self::cursorOf('["2026-02-30 10:00:00","list",5]')]],
            'an array parameter' => [['cursor' => ['x']]],
            // Out of what the columns hold, which PostgreSQL would refuse to compare with.
            'an index beyond an INT' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","list",2147483648]')]],
            'the year zero' => [['cursor' => self::cursorOf('["0000-01-01 00:00:00","list",5]')]],
            'a year before DATETIME\'s' => [['cursor' => self::cursorOf('["0999-12-31 23:59:59","list",5]')]],
            'a list id longer than its column' => [['cursor' => self::cursorOf(
                '["2026-11-11 10:00:00","' . str_repeat('l', 65) . '",5]',
            )]],
            // PostgreSQL refuses to compare a string carrying a NUL byte.
            'a list id carrying a NUL byte' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","list\u0000",5]')]],
            'a list id carrying a space' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00","a list",5]')]],
            // The date parser throws on a NUL byte rather than answering false.
            'a moment carrying a NUL byte' => [['cursor' => self::cursorOf('["2026-11-11 10:00:00\u0000","list",5]')]],
        ];
    }


    /**
     * The cursor names its moment in UTC, as the moment is stored and as the cursor is read back, whatever zone the
     * last credential's moment came in.
     */
    public function testNamesTheNextPageInUtcWhateverZoneTheLastCredentialsMomentIsIn(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord());

        $records = $this->credentialEntries(501);
        $zagreb = new DateTimeZone('Europe/Zagreb');
        $last = $records[499];
        $records[499] = new StatusListEntryRecord(
            $last->getStatusListId(),
            $last->getIdx(),
            true,
            0,
            null,
            $last->getCredentialId(),
            $last->getCredentialIdHash(),
            $last->getCredentialConfigurationId(),
            null,
            new DateTimeImmutable('2026-11-01 11:08:19', $zagreb),
            null,
            self::OFFER_ID,
        );
        $after = [];
        $this->statusListEntryRepositoryMock->method('findLinkedToOffer')->willReturnCallback(
            function (string $offerId, int $limit, ?StatusListEntryPosition $position) use (&$after, $records): array {
                $after[] = $position;

                return $position === null ? $records : [];
            },
        );

        $first = $this->jsonOf($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));
        $this->sut()->credentialOfferDetails(
            $this->detailsRequest(['cursor' => (string)($first['next_cursor'] ?? '')]),
            self::OFFER_ID,
        );

        $this->assertInstanceOf(StatusListEntryPosition::class, $after[1] ?? null);
        $this->assertSame(
            '2026-11-01 10:08:19',
            $after[1]->getIssuedAt()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s'),
        );
    }


    /**
     * Ownership is settled before the cursor is looked at, so a caller which does not own the offer learns
     * nothing from how a cursor is judged: it is told not found, not that its cursor is malformed.
     */
    public function testAnswersNotFoundBeforeJudgingTheCursorOfAnOfferTheCallerMayNotSee(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord('Library system'));
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $this->assertNotFound($this->sut()->credentialOfferDetails(
            $this->detailsRequest(['cursor' => 'a+b']),
            self::OFFER_ID,
        ));
    }


    /**
     * A storage failure reading the offer is this server's, answered as one in JSON rather than left to reach
     * SimpleSAMLphp's HTML error page.
     */
    public function testAnswersAFailureToReadTheOfferAsAJsonServerError(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')
            ->willThrowException(new RuntimeException('database gone'));
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $response = $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertSame('server_error', $this->jsonOf($response)['error'] ?? null);
    }


    /**
     * And likewise a failure reading the credentials of an offer which is the caller's.
     */
    public function testAnswersAFailureToReadTheCredentialsAsAJsonServerError(): void
    {
        $this->authorizeDetailsAs($this->employeeCaller());
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord());
        $this->statusListEntryRepositoryMock->method('findLinkedToOffer')
            ->willThrowException(new RuntimeException('database gone'));

        $response = $this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID);

        $this->assertSame(Response::HTTP_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertSame('server_error', $this->jsonOf($response)['error'] ?? null);
    }


    /**
     * A token which may offer more than the offer holds still sees its offer, but a token which may offer
     * everything is not thereby every caller's: ownership is not lifted by an unlimited list.
     */
    public function testAnUnlimitedCallerStillSeesOnlyItsOwnOffers(): void
    {
        $this->authorizeDetailsAs(
            new ApiCaller('Library system', CredentialConfigurationLimit::fromConfiguredIds(['*'])),
        );
        $this->credentialOfferRepositoryMock->method('find')->willReturn($this->offerRecord('HR system'));
        $this->statusListEntryRepositoryMock->expects($this->never())->method('findLinkedToOffer');

        $this->assertNotFound($this->sut()->credentialOfferDetails($this->detailsRequest(), self::OFFER_ID));
    }
}
