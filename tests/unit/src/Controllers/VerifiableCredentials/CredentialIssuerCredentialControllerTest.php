<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use ArrayObject;
use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use Jose\Component\KeyManagement\JWKFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionClass;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerCredentialController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\ErrorResponder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusUpdaterInterface;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusIssuer;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\AccessTokenTypesEnum;
use SimpleSAML\OpenID\Codebooks\AtContextsEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Codebooks\TermsOfUseTypesEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Helpers as VcHelpers;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\SdJwt\Disclosure;
use SimpleSAML\OpenID\SdJwt\DisclosureBag;
use SimpleSAML\OpenID\SdJwt\Factories\DisclosureBagFactory;
use SimpleSAML\OpenID\SdJwt\Factories\DisclosureFactory;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\TokenStatusList\StatusClaim;
use SimpleSAML\OpenID\TokenStatusList\StatusReference;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\VerifiableCredentials as VerifiableCredentialsService;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use SimpleSAML\OpenID\VerifiableCredentials\SdJwtVc\Factories\SdJwtVcFactory;
use SimpleSAML\OpenID\VerifiableCredentials\SdJwtVc\SdJwtVc;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel\Factories\JwtVcJsonFactory;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel\JwtVcJson;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel2\Factories\VcSdJwtFactory;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel2\VcSdJwt;
use stdClass;
use Stringable;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

#[AllowMockObjectsWithoutExpectations]
class CredentialIssuerCredentialControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'test_id';

    /**
     * The type an SD-JWT VC configuration advertises, other than its id, so that a test can tell which one a
     * credential states.
     */
    protected const string VCT = 'urn:example:TestCredentialType';

    protected const string ISSUER = 'https://issuer.com';

    protected const string ISSUER_DID = 'did:jwk:test';

    protected const string STATUS_LIST_URI = 'https://issuer.com/module.php/oidc/statuslist/list-1';

    protected const string HOLDER_DID = 'did:jwk:holder';

    protected const string CREDENTIAL_ENDPOINT = 'https://issuer.com/module.php/oidc/credential';


    protected MockObject $resourceServerMock;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $moduleConfigMock;

    protected MockObject $routesMock;

    protected MockObject $psrHttpBridgeMock;

    protected MockObject $verifiableCredentialsMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $vciIssuerIdentityResolverMock;

    protected MockObject $vciIssuerIdentityRepositoryMock;

    protected MockObject $openId4VciProofValidatorMock;

    protected MockObject $vciContextResolverMock;

    protected MockObject $credentialStatusIssuerMock;

    protected Helpers $helpers;

    protected MockObject $errorResponderMock;

    /** What the error responder last answered with, so that a test can tell its answer reached the client. */
    protected ?Response $errorResponderResponse = null;

    /** @var array<array<string,mixed>> Payloads handed to whichever credential factory was used. */
    protected array $signedPayloads = [];

    /**
     * @var array<array{key: mixed, algorithm: mixed, format: string}> What each of those payloads was signed with,
     * by the factory of which format.
     */
    protected array $signedWith = [];

    protected MockObject $vciSignatureKeyPairMock;

    protected MockObject $vciPrivateKeyMock;

    /** A real key for the active signing key pair to hand out, for a test which signs for real. */
    protected ?JwkDecorator $signingKey = null;

    /** The library's own facade in place of the double, for a test which builds credentials for real. */
    protected ?VerifiableCredentialsService $verifiableCredentials = null;

    protected VciCredentialBindingPolicyEnum $bindingPolicy;

    /** What the configuration rounds time claims to; no time at all, so rounding is off, unless a test sets it. */
    protected DateInterval $timeClaimGranularity;

    protected MockObject $accessTokenMock;

    protected ?UserEntity $userEntity = null;

    /**
     * The scenario the collaborators read, rather than what a test re-stubs on them.
     *
     * A mock keeps the first matcher registered for a method, so a second `method('isRevoked')` in a
     * test body would silently never fire and the test would pass against the happy path it meant to
     * spoil. Everything a test varies is therefore a property here, read through `willReturnCallback`.
     */
    protected ?FlowTypeEnum $flowType = null;

    /** The resource server's refusal of the access token, as it refuses one which is missing or invalid. */
    protected ?OAuthServerException $accessTokenRefusal = null;

    protected bool $accessTokenIsFound = true;

    protected bool $accessTokenIsRevoked = false;

    protected ?string $accessTokenUserIdentifier = null;

    /** @var ?array<array-key,mixed> */
    protected ?array $authorizationDetails = null;

    protected ?string $issuerState = null;

    /** Whether the access token's client is the generic one standing in for wallets which are not registered. */
    protected bool $clientIsGeneric = false;

    /** @var \SimpleSAML\Module\oidc\Entities\ScopeEntity[] The scopes the access token grants. */
    protected array $tokenScopes = [];

    /** @var ?array<string,mixed> */
    protected ?array $credentialConfiguration = null;

    /** @var array<string,mixed> */
    protected array $requestData = [];

    /** @var array<?\SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof> */
    protected array $validatedProofs = [];

    protected ?Throwable $proofValidationException = null;

    /** @var array<string,mixed> */
    protected array $userClaims = [];

    /** @var array<array-key,mixed> */
    protected array $validClaimPaths = [];

    /** @var array<array-key,mixed> */
    protected array $attributeToClaimPathMap = [];

    /** @var list<list<mixed>> */
    protected array $mandatoryClaimPaths = [];

    protected ?string $configurationFault = null;

    /** @var array<array{error: string, description: string, httpCode: int}> Refusals the endpoint answered with. */
    protected array $errorResponses = [];

    /** @var \League\OAuth2\Server\Exception\OAuthServerException[] OAuth errors handed to the error responder. */
    protected array $oauthErrors = [];

    /** @var array<array<array-key,mixed>> Successful responses the endpoint answered with. */
    protected array $jsonResponses = [];

    /** @var \SimpleSAML\OpenID\SdJwt\DisclosureBag[] One per credential built in an SD-JWT format. */
    protected array $disclosureBags = [];

    /**
     * @var array<?\SimpleSAML\OpenID\SdJwt\DisclosureBag> The bag each credential was signed with, in the order
     * of $signedPayloads; null for a format which has none.
     */
    protected array $signedDisclosureBags = [];

    /** The scheme the resource server says the access token was presented under. */
    protected string $presentedScheme = 'Bearer';

    /** @var string[] The resource URLs the resource server was asked to check the token for. */
    protected array $resourceUrls = [];


    public function setUp(): void
    {
        $this->resourceServerMock = $this->createMock(ResourceServer::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->routesMock = $this->createMock(Routes::class);
        $this->psrHttpBridgeMock = $this->createMock(PsrHttpBridge::class);
        $this->verifiableCredentialsMock = $this->createMock(VerifiableCredentialsService::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->method('resolve')->willReturn(
            new VciIssuerIdentity(
                VciIssuerIdentifierModeEnum::DidJwk,
                self::ISSUER_DID,
                self::ISSUER_DID . '#0',
            ),
        );
        $this->vciIssuerIdentityRepositoryMock = $this->createMock(VciIssuerIdentityRepository::class);
        $this->openId4VciProofValidatorMock = $this->createMock(OpenId4VciProofValidator::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);
        $this->credentialStatusIssuerMock = $this->createMock(CredentialStatusIssuer::class);
        $this->helpers = new Helpers();
        $this->errorResponderMock = $this->createMock(ErrorResponder::class);
        $this->errorResponderResponse = null;
        $this->signedPayloads = [];
        $this->signedWith = [];
        $this->signingKey = null;
        $this->verifiableCredentials = null;
        $this->errorResponses = [];
        $this->oauthErrors = [];
        $this->jsonResponses = [];
        $this->disclosureBags = [];
        $this->signedDisclosureBags = [];
        $this->presentedScheme = 'Bearer';
        $this->resourceUrls = [];
        $this->routesMock->method('urlCredentialIssuerCredential')->willReturn(self::CREDENTIAL_ENDPOINT);

        // A request which should be issued: a pre-authorized-code access token, found and unrevoked,
        // naming a user and a credential configuration this issuer supports, which the token grants. Each
        // test spoils exactly one of these, so a check which stopped refusing falls through to the success
        // path and fails for the absent refusal rather than passing.
        $this->flowType = FlowTypeEnum::VciPreAuthorizedCode;
        $this->accessTokenRefusal = null;
        $this->accessTokenIsFound = true;
        $this->accessTokenIsRevoked = false;
        $this->accessTokenUserIdentifier = 'user123';
        $this->authorizationDetails = null;
        $this->issuerState = null;
        $this->clientIsGeneric = false;
        $this->tokenScopes = [new ScopeEntity(self::CONFIGURATION_ID)];
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
        ];
        $this->requestData = [ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID];
        $this->validatedProofs = [];
        $this->proofValidationException = null;
        $this->userClaims = [];
        $this->validClaimPaths = [];
        $this->attributeToClaimPathMap = [];
        $this->mandatoryClaimPaths = [];
        $this->configurationFault = null;

        // VCI must be enabled in constructor
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getDpopSigningAlgorithms')->willReturn(['ES256', 'PS256']);
        $this->moduleConfigMock->method('getVciIssuerIdentifier')
            ->willReturn(new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk));
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturnCallback(fn(): ?array => $this->credentialConfiguration);
        $this->moduleConfigMock->method('getVciValidCredentialClaimPathsFor')
            ->willReturnCallback(fn(): array => $this->validClaimPaths);
        $this->moduleConfigMock->method('getVciUserAttributeToCredentialClaimPathMapFor')
            ->willReturnCallback(fn(): array => $this->attributeToClaimPathMap);
        $this->moduleConfigMock->method('getVciMandatoryCredentialClaimPathsFor')
            ->willReturnCallback(fn(): array => $this->mandatoryClaimPaths);
        // What ModuleConfig would say of the configuration is its own subject (ModuleConfigTest); here it is the
        // scenario's.
        $this->moduleConfigMock->method('findFaultInVciCredentialConfiguration')
            ->willReturnCallback(fn(): ?string => $this->configurationFault);
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound;
        $this->moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturnCallback(fn(): VciCredentialBindingPolicyEnum => $this->bindingPolicy);
        $this->timeClaimGranularity = new DateInterval('PT0S');
        $this->moduleConfigMock->method('getVciTimeClaimGranularity')
            ->willReturnCallback(fn(): DateInterval => $this->timeClaimGranularity);

        $this->prepareRequestPipeline();
        $this->prepareResponses();
        $this->prepareUser();
        $this->prepareSigningKey();
        $this->prepareCredentialFactories();
    }


    protected function prepareRequestPipeline(): void
    {
        $psrRequestMock = $this->createMock(ServerRequestInterface::class);
        $psrFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrFactoryMock->method('createRequest')->willReturn($psrRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrFactoryMock);

        $authorizationMock = $this->createMock(ServerRequestInterface::class);
        $authorizationMock->method('getAttribute')->willReturnCallback(
            fn(string $name): string => match ($name) {
                'oauth_access_token_id' => 'token_id',
                BearerTokenValidator::ATTRIBUTE_ACCESS_TOKEN_SCHEME => $this->presentedScheme,
            },
        );
        $this->resourceServerMock->method('validateAuthenticatedRequest')->willReturnCallback(
            function (
                ServerRequestInterface $request,
                string $resourceUrl,
            ) use ($authorizationMock): ServerRequestInterface {
                $this->resourceUrls[] = $resourceUrl;

                if ($this->accessTokenRefusal !== null) {
                    throw $this->accessTokenRefusal;
                }

                return $authorizationMock;
            },
        );

        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')
            ->willReturnCallback(fn(): array => $this->requestData);

        $this->accessTokenMock = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenMock->method('getFlowTypeEnum')
            ->willReturnCallback(fn(): ?FlowTypeEnum => $this->flowType);
        $this->accessTokenMock->method('getUserIdentifier')
            ->willReturnCallback(fn(): ?string => $this->accessTokenUserIdentifier);
        $this->accessTokenMock->method('getAuthorizationDetails')
            ->willReturnCallback(fn(): ?array => $this->authorizationDetails);
        $this->accessTokenMock->method('getIssuerState')
            ->willReturnCallback(fn(): ?string => $this->issuerState);
        $clientMock = $this->createMock(ClientEntityInterface::class);
        $clientMock->method('isGeneric')->willReturnCallback(fn(): bool => $this->clientIsGeneric);
        $this->accessTokenMock->method('getClient')->willReturn($clientMock);
        $this->accessTokenMock->method('getScopes')->willReturnCallback(fn(): array => $this->tokenScopes);
        $this->accessTokenMock->method('isRevoked')
            ->willReturnCallback(fn(): bool => $this->accessTokenIsRevoked);
        $this->accessTokenRepositoryMock->method('findById')->with('token_id')->willReturnCallback(
            fn(): ?AccessTokenEntity => $this->accessTokenIsFound ? $this->accessTokenMock : null,
        );

        // What a key proof has to satisfy to get this far is OpenId4VciProofValidatorTest's subject.
        $this->openId4VciProofValidatorMock->method('validateRequest')->willReturnCallback(
            function (): array {
                if ($this->proofValidationException !== null) {
                    throw $this->proofValidationException;
                }

                return $this->validatedProofs;
            },
        );
    }


    /**
     * What the endpoint answered with, recorded rather than expected per test, so that a test can say
     * which refusal it wanted instead of only that some refusal happened.
     */
    protected function prepareResponses(): void
    {
        // The real Routes answers, so that a test can read the status, the content type and the body a client
        // gets; the double records what it was handed.
        $routes = new Routes($this->createStub(ModuleConfig::class), $this->createStub(SspBridge::class));
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            function (
                ?array $data = null,
                int $status = 200,
                array $headers = [],
                bool $json = false,
            ) use ($routes): JsonResponse {
                $this->jsonResponses[] = $data ?? [];

                return $routes->newJsonResponse($data, $status, $headers, $json);
            },
        );

        $this->routesMock->method('newJsonErrorResponse')->willReturnCallback(
            function (string $error, string $description, int $httpCode = 500, array $headers = []): JsonResponse {
                // Printable ASCII without the double quote and the backslash (OpenID4VCI 1.0 section 8.3.1.2),
                // as written here rather than as Routes cuts it down, so every refusal a test provokes is checked.
                $this->assertMatchesRegularExpression('/^[\x20\x21\x23-\x5B\x5D-\x7E]*$/', $description);

                $this->errorResponses[] = [
                    'error' => $error,
                    'description' => $description,
                    'httpCode' => $httpCode,
                ];

                return new JsonResponse(
                    ['error' => $error, 'error_description' => $description],
                    $httpCode,
                    $headers,
                );
            },
        );

        // The real responder answers, so that the response carries what the error says it should (its challenge
        // above all); the double records what it was handed.
        $errorResponder = new ErrorResponder(
            $this->createStub(PsrHttpBridge::class),
            $this->createStub(LoggerService::class),
        );
        $this->errorResponderMock->method('forExceptionJson')->willReturnCallback(
            function (OAuthServerException $exception) use ($errorResponder): Response {
                $this->oauthErrors[] = $exception;

                return $this->errorResponderResponse = $errorResponder->forExceptionJson($exception);
            },
        );
    }


    protected function prepareUser(): void
    {
        $userEntity = $this->createMock(UserEntity::class);
        $userEntity->method('getClaims')->willReturnCallback(fn(): array => $this->userClaims);
        $this->userEntity = $userEntity;
        $this->userRepositoryMock->method('getUserEntityByIdentifier')
            ->willReturnCallback(fn(): ?UserEntity => $this->userEntity);
    }


    protected function prepareSigningKey(): void
    {
        $this->vciPrivateKeyMock = $this->createMock(JwkDecorator::class);
        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPrivateKey')->willReturnCallback(
            fn(): object => $this->signingKey ?? $this->vciPrivateKeyMock,
        );
        $keyPairMock->method('getKeyId')->willReturn('vci-01');
        $publicKey = (new JwkDecoratorFactory())->fromData(['kty' => 'EC']);
        $keyPairMock->method('getPublicKey')->willReturn($publicKey);

        $this->vciSignatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $this->vciSignatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $this->vciSignatureKeyPairMock->method('getSignatureAlgorithm')
            ->willReturn(SignatureAlgorithmEnum::ES256);

        $this->moduleConfigMock->method('getActiveVciSignatureKeyPair')
            ->willReturn($this->vciSignatureKeyPairMock);

        // The real helpers, so that an attribute mapped to a nested claim path actually lands there and
        // the assertions below are about the credential rather than about a mock having been called.
        $this->verifiableCredentialsMock->method('helpers')->willReturn(new VcHelpers());
    }


    /**
     * Every credential factory records the payload it was asked to sign, which is where the claims
     * under test end up.
     */
    protected function prepareCredentialFactories(): void
    {
        $jwtVcJsonMock = $this->createMock(JwtVcJson::class);
        $jwtVcJsonMock->method('getToken')->willReturn('vc_token');
        $jwtVcJsonFactoryMock = $this->createMock(JwtVcJsonFactory::class);
        $jwtVcJsonFactoryMock->method('fromData')->willReturnCallback(
            function (mixed $key, mixed $algorithm, array $payload) use ($jwtVcJsonMock): JwtVcJson {
                $this->signedPayloads[] = $payload;
                $this->signedDisclosureBags[] = null;
                $this->signedWith[] = [
                    'key' => $key,
                    'algorithm' => $algorithm,
                    'format' => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                ];

                return $jwtVcJsonMock;
            },
        );
        $this->verifiableCredentialsMock->method('jwtVcJsonFactory')->willReturn($jwtVcJsonFactoryMock);

        $sdJwtVcMock = $this->createMock(SdJwtVc::class);
        $sdJwtVcMock->method('getToken')->willReturn('sd_jwt_token');
        $sdJwtVcFactoryMock = $this->createMock(SdJwtVcFactory::class);
        $sdJwtVcFactoryMock->method('fromData')->willReturnCallback(
            function (
                mixed $key,
                mixed $algorithm,
                array $payload,
                array $header = [],
                ?DisclosureBag $disclosureBag = null,
            ) use ($sdJwtVcMock): SdJwtVc {
                $this->signedPayloads[] = $payload;
                $this->signedDisclosureBags[] = $disclosureBag;
                $this->signedWith[] = [
                    'key' => $key,
                    'algorithm' => $algorithm,
                    'format' => CredentialFormatIdentifiersEnum::DcSdJwt->value,
                ];

                return $sdJwtVcMock;
            },
        );
        $this->verifiableCredentialsMock->method('sdJwtVcFactory')->willReturn($sdJwtVcFactoryMock);

        $vcSdJwtMock = $this->createMock(VcSdJwt::class);
        $vcSdJwtMock->method('getToken')->willReturn('vc_sd_jwt_token');
        $vcSdJwtFactoryMock = $this->createMock(VcSdJwtFactory::class);
        $vcSdJwtFactoryMock->method('fromData')->willReturnCallback(
            function (
                mixed $key,
                mixed $algorithm,
                array $payload,
                array $header = [],
                ?DisclosureBag $disclosureBag = null,
            ) use ($vcSdJwtMock): VcSdJwt {
                $this->signedPayloads[] = $payload;
                $this->signedDisclosureBags[] = $disclosureBag;
                $this->signedWith[] = [
                    'key' => $key,
                    'algorithm' => $algorithm,
                    'format' => CredentialFormatIdentifiersEnum::VcSdJwt->value,
                ];

                return $vcSdJwtMock;
            },
        );
        $this->verifiableCredentialsMock->method('vcSdJwtFactory')->willReturn($vcSdJwtFactoryMock);

        // One bag per credential built, kept so that what an SD-JWT format put into it can be read
        // back. Real disclosures, for the same reason the helpers above are real: what a disclosure
        // ends up holding is the thing under test.
        $disclosureBagFactoryMock = $this->createMock(DisclosureBagFactory::class);
        $disclosureBagFactoryMock->method('build')->willReturnCallback(
            function (): DisclosureBag {
                $disclosureBag = new DisclosureBag();
                $this->disclosureBags[] = $disclosureBag;

                return $disclosureBag;
            },
        );
        $this->verifiableCredentialsMock->method('disclosureBagFactory')->willReturn($disclosureBagFactoryMock);
        $this->verifiableCredentialsMock->method('disclosureFactory')
            ->willReturn(new DisclosureFactory(new VcHelpers()));
    }


    /**
     * Issue against a proof-bound configuration, with the key proofs already validated.
     *
     * What a key proof has to satisfy before it gets this far is OpenId4VciProofValidatorTest's
     * subject; here the validator stands in for it and hands back what it resolved, so these tests are
     * about what issuance does with that.
     *
     * @param string[] $proofJwts
     */
    protected function issue(
        string $format = CredentialFormatIdentifiersEnum::JwtVcJson->value,
        array $proofJwts = ['jwt1'],
        ?array $inlineKey = null,
    ): Response {
        // An SD-JWT VC configuration advertises the type its credentials state, which is not its id.
        $this->credentialConfiguration = [ClaimsEnum::Format->value => $format] +
        ($format === CredentialFormatIdentifiersEnum::DcSdJwt->value ? [ClaimsEnum::Vct->value => self::VCT] : []);

        $this->requestData = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => $proofJwts],
        ];

        $validatedProofs = [];
        foreach ($proofJwts as $ignored) {
            $validatedProofs[] = $this->validatedProof($inlineKey);
        }
        $this->validatedProofs = $validatedProofs;

        return $this->dispatch();
    }


    /**
     * A key proof which passed every check, resolved to the holder it names.
     *
     * @param ?array<array-key,mixed> $inlineKey The key a proof carried inline, for a proof which named
     * no verification method.
     * @param string $holderDid The DID the proof resolved to, a `did:jwk` made from the key for an inline one.
     */
    protected function validatedProof(
        ?array $inlineKey = null,
        string $holderDid = self::HOLDER_DID,
    ): ValidatedOpenId4VciProof {
        return new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            $holderDid,
            $inlineKey === null ? $holderDid . '#0' : null,
            $inlineKey,
            hash('sha256', $holderDid),
        );
    }


    /**
     * @param ?array<string,mixed> $requestData Defaults to the scenario's own request parameters. Given, they
     * become the scenario's, since those are what the request parameters resolver hands the endpoint.
     */
    protected function dispatch(?array $requestData = null): Response
    {
        $this->requestData = $requestData ?? $this->requestData;

        $request = new Request([], [], [], [], [], [], json_encode($this->requestData));
        $request->setMethod('POST');

        return $this->sut()->credential($request);
    }


    /**
     * @return array<array-key,mixed> The claims the credential built by the last issuance states about
     * its subject.
     */
    protected function credentialSubjectOfFirstCredential(): array
    {
        $payload = $this->signedPayloads[0] ?? [];

        /** @psalm-suppress MixedAssignment, MixedArrayAccess */
        $credentialSubject = $payload[ClaimsEnum::Vc->value][ClaimsEnum::Credential_Subject->value]
        ?? $payload[ClaimsEnum::Credential_Subject->value]
        ?? [];

        return (array)$credentialSubject;
    }


    protected function assertRefusedWith(string $error, int $httpCode): void
    {
        $this->assertCount(1, $this->errorResponses);
        $this->assertSame($error, $this->errorResponses[0]['error']);
        $this->assertSame($httpCode, $this->errorResponses[0]['httpCode']);
    }


    /**
     * A 401 carrying the challenges HTTP requires of every 401 (RFC 9110 section 15.5.2) and RFC 6750 section 3 of
     * a protected resource refusing a request for its access token, here naming the error, since a token arrived
     * and was refused (section 3.1): in the Bearer challenge, the scheme it came under, with the DPoP one beside it
     * (RFC 9449 section 7.2, Figure 18).
     */
    protected function assertChallengesTheRefusedToken(Response $response): void
    {
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            'Bearer error="invalid_token", DPoP algs="ES256 PS256"',
            $response->headers->get('WWW-Authenticate'),
        );
    }


    /**
     * The request ended in an OAuth error, which the error responder was handed to answer, and nothing was
     * issued.
     */
    protected function assertAnsweredWithOAuthError(string $errorType, int $httpCode): void
    {
        $this->assertCount(1, $this->oauthErrors);
        $this->assertSame($errorType, $this->oauthErrors[0]->getErrorType());
        $this->assertSame($httpCode, $this->oauthErrors[0]->getHttpStatusCode());
        $this->assertSame([], $this->errorResponses);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A deployment with Verifiable Credentials switched off is refused here, and refused without an
     * issuer identity being resolved.
     *
     * Resolving one builds the DID facade, which reads the DID destination settings and instantiates
     * the class `vci_cache_adapter` names - neither of which such a deployment has any reason to have
     * configured correctly, or at all. The container resolves every constructor argument before the
     * constructor body runs, so anything which builds that facade eagerly answers this endpoint in
     * place of the guard, with a 500 where a 403 was intended.
     */
    public function testRefusesWhenVciIsDisabledWithoutResolvingAnIssuerIdentity(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(false);

        $this->vciIssuerIdentityResolverMock = $this->createMock(VciIssuerIdentityResolver::class);
        $this->vciIssuerIdentityResolverMock->expects($this->never())->method('resolve');

        $this->expectException(OidcServerException::class);

        $this->sut();
    }


    protected function sut(): CredentialIssuerCredentialController
    {
        return new CredentialIssuerCredentialController(
            $this->resourceServerMock,
            $this->accessTokenRepositoryMock,
            $this->moduleConfigMock,
            $this->routesMock,
            $this->psrHttpBridgeMock,
            $this->verifiableCredentials ?? $this->verifiableCredentialsMock,
            $this->loggerServiceMock,
            $this->requestParamsResolverMock,
            $this->userRepositoryMock,
            $this->vciIssuerIdentityResolverMock,
            $this->vciIssuerIdentityRepositoryMock,
            $this->openId4VciProofValidatorMock,
            $this->vciContextResolverMock,
            $this->credentialStatusIssuerMock,
            $this->helpers,
            $this->errorResponderMock,
        );
    }


    /**
     * @throws \SimpleSAML\OpenID\Exceptions\StatusListException
     * @throws \SimpleSAML\OpenID\Exceptions\InvalidValueException
     */
    protected function statusClaim(int $idx = 42): StatusClaim
    {
        return new StatusClaim(new StatusReference(self::STATUS_LIST_URI, $idx));
    }


    /**
     * The other half of what issuer metadata promises. The credential configuration advertises the
     * active signing key's algorithm, so issuance has to reach for that same key rather than for
     * whichever other pair happens to be configured -- otherwise a wallet is handed a credential it was
     * told it would not receive. The advertising half is pinned by
     * CredentialIssuerConfigurationControllerTest.
     */
    public function testSignsEveryCredentialWithTheActiveSigningKey(): void
    {
        $this->issue(proofJwts: ['jwt1', 'jwt2']);

        $this->assertCount(2, $this->signedWith);

        foreach ($this->signedWith as $signedWith) {
            $this->assertSame($this->vciPrivateKeyMock, $signedWith['key']);
            $this->assertSame(SignatureAlgorithmEnum::ES256, $signedWith['algorithm']);
        }
    }


    /**
     * The credential is issued to the holder identifier the key proof resolved to, and says so in the
     * same two places it always has.
     */
    public function testBindsTheCredentialToWhatTheProofResolvedTo(): void
    {
        $this->issue();

        $payload = $this->signedPayloads[0];

        $this->assertSame(self::HOLDER_DID, $payload[ClaimsEnum::Sub->value] ?? null);
        $this->assertSame(
            self::HOLDER_DID,
            $payload[ClaimsEnum::Vc->value][ClaimsEnum::Credential_Subject->value][ClaimsEnum::Id->value] ?? null,
        );
    }


    /**
     * OpenID4VCI 1.0 section 15.4.1: an issuer should discard values a verifier could track the user by, the key a
     * credential is bound to among them. At every log level, nothing names the holder, its key or the proof; the
     * issuance line says which kind of holder identifier it was.
     */
    public function testKeepsTheHolderKeyAndTheProofOutOfTheLog(): void
    {
        $logged = [];
        foreach (['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use (&$logged): void {
                    $logged[] = [(string)$message, $context];
                },
            );
        }

        $inlineKey = ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'holder-key-x', 'y' => 'holder-key-y'];
        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value, ['holder-proof-jwt'], $inlineKey);

        $this->assertCount(1, $this->signedPayloads);
        $log = json_encode($logged, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        foreach ([self::HOLDER_DID, 'holder-key-x', 'holder-key-y', 'holder-proof-jwt'] as $value) {
            $this->assertStringNotContainsString($value, $log);
        }

        $issuanceLines = array_values(array_filter(
            $logged,
            static fn(array $line): bool => $line[0] === 'Signing and issuing verifiable credential.',
        ));
        $this->assertCount(1, $issuanceLines);
        $this->assertSame('did:jwk', $issuanceLines[0][1]['holderDidMethod'] ?? null);
    }


    /**
     * `cnf` is where a verifier reads what a credential is held by, and `credentialSubject.id` is not
     * equivalent to it. The claim was assembled inside two of the three format branches, so the third
     * issued credentials which looked unbound however carefully the proof behind them was checked.
     */
    public function testStatesTheConfirmedKeyInEveryFormat(): void
    {
        $issuableFormats = [
            CredentialFormatIdentifiersEnum::JwtVcJson,
            CredentialFormatIdentifiersEnum::DcSdJwt,
            CredentialFormatIdentifiersEnum::VcSdJwt,
        ];

        foreach ($issuableFormats as $format) {
            $this->setUp();
            $this->issue($format->value);

            $this->assertSame(
                [ClaimsEnum::Kid->value => self::HOLDER_DID . '#0'],
                $this->signedPayloads[0][ClaimsEnum::Cnf->value] ?? null,
                sprintf('The %s format did not state the key its credential is held by.', $format->value),
            );
        }
    }


    /**
     * A proof carrying its key inline names no verification method, so there is no `kid` to confirm.
     * Saying nothing at all was the same defect the other way round: a signature had been verified and
     * nothing in the credential said which key it was verified against.
     */
    public function testConfirmsAnInlineKeyByTheKeyItself(): void
    {
        $holderJwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-value', 'y' => 'y-value'];

        $this->issue(inlineKey: $holderJwk);

        $this->assertSame(
            [ClaimsEnum::Jwk->value => $holderJwk],
            $this->signedPayloads[0][ClaimsEnum::Cnf->value] ?? null,
        );
    }


    /**
     * A credential bound to a key names its holder by `cnf` alone, whichever way the proof named the key.
     * The subject the proof resolved to is that key's DID, one per key, so it would set apart the
     * credentials of a batch, which OpenID4VCI 1.0 section 3.3.2 has share one Credential Dataset.
     *
     * @param ?array<string,string> $inlineKey
     */
    #[DataProvider('keyBindingProvider')]
    public function testAKeyBoundSdJwtVcNamesItsHolderByCnfAlone(?array $inlineKey): void
    {
        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value, inlineKey: $inlineKey);

        $payload = $this->signedPayloads[0];

        $this->assertArrayHasKey(ClaimsEnum::Cnf->value, $payload);
        $this->assertArrayNotHasKey(ClaimsEnum::Sub->value, $payload);
    }


    /**
     * @return array<string,array{0: ?array<string,string>}>
     */
    public static function keyBindingProvider(): array
    {
        return [
            'a verification method named by kid' => [null],
            'a key sent inline' => [['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-value', 'y' => 'y-value']],
        ];
    }


    /**
     * The W3C data model names its holder as the credential subject, so the formats built on it keep the
     * subject the proof resolved to, beside `cnf`.
     */
    public function testTheDataModelTwoFormatStillNamesTheHolderAsItsSubject(): void
    {
        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        $payload = $this->signedPayloads[0];

        $this->assertSame(self::HOLDER_DID, $payload[ClaimsEnum::Sub->value] ?? null);
        $this->assertSame(
            self::HOLDER_DID,
            $this->credentialSubjectOfFirstCredential()[ClaimsEnum::Id->value] ?? null,
        );
    }


    /**
     * The credentials of one batch share their format and Credential Dataset (OpenID4VCI 1.0 section 3.3.2), and
     * their rounded times (RFC 9901 section 10.1): the claims about the user are the same in each, in the body or
     * in the disclosures, as the format carries them. What sets them apart is what identifies each of them: the
     * credential identifier, and the key it is bound to, which the W3C formats also name as their subject (the
     * DID of that key).
     *
     * @param list<list<string>> $identifyingPaths
     */
    #[DataProvider('batchFormatProvider')]
    public function testTheCredentialsOfABatchDifferOnlyInWhatIdentifiesEach(
        CredentialFormatIdentifiersEnum $format,
        array $identifyingPaths,
    ): void {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));
        $this->timeClaimGranularity = new DateInterval('P1D');
        $this->credentialConfiguration = [ClaimsEnum::Format->value => $format->value] +
        ($format === CredentialFormatIdentifiersEnum::DcSdJwt ? [ClaimsEnum::Vct->value => self::VCT] : []);
        $this->validClaimPaths = [
            [ClaimsEnum::Credential_Subject->value, 'given_name'],
            [ClaimsEnum::Credential_Subject->value, 'family_name'],
        ];
        $this->attributeToClaimPathMap = [
            ['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']],
            ['sn' => [ClaimsEnum::Credential_Subject->value, 'family_name']],
        ];
        $this->userClaims = ['givenName' => ['John'], 'sn' => ['Doe']];
        $this->requestData = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => ['jwt1', 'jwt2']],
        ];
        $this->validatedProofs = [
            $this->validatedProof(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-1', 'y' => 'y-1'], 'did:jwk:first'),
            $this->validatedProof(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x-2', 'y' => 'y-2'], 'did:jwk:second'),
        ];

        $this->dispatch();

        $this->assertCount(2, $this->signedPayloads);
        $this->assertSame([$format->value, $format->value], array_column($this->signedWith, 'format'));
        [$first, $second] = $this->signedPayloads;

        foreach ($identifyingPaths as $path) {
            $this->assertNotNull(self::claimAt($first, $path), implode('.', $path));
            $this->assertNotSame(self::claimAt($first, $path), self::claimAt($second, $path), implode('.', $path));
        }

        $this->assertSame(
            self::withoutClaims($first, $identifyingPaths),
            self::withoutClaims($second, $identifyingPaths),
        );
        $this->assertSame($this->disclosuresOfCredential(0), $this->disclosuresOfCredential(1));
        $this->assertSame(['John', 'Doe'], $this->userClaimValuesOfCredential(0));
        $this->assertArrayHasKey(ClaimsEnum::Iat->value, $first);
        $this->assertArrayHasKey(ClaimsEnum::Exp->value, $first);
    }


    /**
     * @return array<string,list<mixed>>
     */
    public static function batchFormatProvider(): array
    {
        $jti = [ClaimsEnum::Jti->value];
        $cnf = [ClaimsEnum::Cnf->value];
        $sub = [ClaimsEnum::Sub->value];

        return [
            'dc+sd-jwt' => [CredentialFormatIdentifiersEnum::DcSdJwt, [$jti, $cnf]],
            'jwt_vc_json' => [
                CredentialFormatIdentifiersEnum::JwtVcJson,
                [
                    $jti,
                    $cnf,
                    $sub,
                    [ClaimsEnum::Vc->value, ClaimsEnum::Id->value],
                    [ClaimsEnum::Vc->value, ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value],
                ],
            ],
            'vc+sd-jwt' => [
                CredentialFormatIdentifiersEnum::VcSdJwt,
                [
                    $jti,
                    $cnf,
                    $sub,
                    [ClaimsEnum::Id->value],
                    [ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value],
                ],
            ],
        ];
    }


    /**
     * @param list<string> $path
     */
    protected static function claimAt(array $claims, array $path): mixed
    {
        $claim = $claims;

        foreach ($path as $member) {
            if (!is_array($claim) || !array_key_exists($member, $claim)) {
                return null;
            }

            /** @psalm-suppress MixedAssignment */
            $claim = $claim[$member];
        }

        return $claim;
    }


    /**
     * @param list<list<string>> $paths
     */
    protected static function withoutClaims(array $claims, array $paths): array
    {
        foreach ($paths as $path) {
            $claims = self::withoutClaim($claims, $path);
        }

        return $claims;
    }


    /**
     * @param list<string> $path
     */
    protected static function withoutClaim(array $claims, array $path): array
    {
        $member = array_shift($path);

        if ($member === null || !array_key_exists($member, $claims)) {
            return $claims;
        }

        if ($path === []) {
            unset($claims[$member]);
        } elseif (is_array($claims[$member])) {
            $claims[$member] = self::withoutClaim($claims[$member], $path);
        }

        return $claims;
    }


    /**
     * What the disclosures the credential at that position was signed with disclose, where and under which name,
     * without their salts: the bag handed to the credential factory, not one merely built on the way.
     *
     * @return list<array{0: array<array-key,mixed>, 1: ?string, 2: mixed}>
     */
    protected function disclosuresOfCredential(int $position): array
    {
        return array_map(
            static fn(Disclosure $disclosure): array => [
                $disclosure->getPath(),
                $disclosure->getName(),
                $disclosure->getValue(),
            ],
            array_values($this->signedDisclosureBags[$position]?->all() ?? []),
        );
    }


    /**
     * The values of the claims about the user in the credential built at that position, in the credential subject
     * of its body or in its disclosures, whichever the format puts them in; the subject identifier left out.
     *
     * @return list<mixed>
     */
    protected function userClaimValuesOfCredential(int $position): array
    {
        $payload = $this->signedPayloads[$position];
        /** @psalm-suppress MixedAssignment */
        $inTheBody = self::claimAt($payload, [ClaimsEnum::Vc->value, ClaimsEnum::Credential_Subject->value]);
        $credentialSubject = (array)($inTheBody ?? self::claimAt($payload, [ClaimsEnum::Credential_Subject->value]));
        unset($credentialSubject[ClaimsEnum::Id->value]);

        return [
            ...array_values($credentialSubject),
            ...array_column($this->disclosuresOfCredential($position), 2),
        ];
    }


    /**
     * Issuance is stated rounded down to the granularity on the UTC epoch, as both `iat` and `nbf`, so it
     * says which period the credential was issued in and not the second.
     */
    #[DataProvider('granularityProvider')]
    public function testStatesTheIssuanceRoundedDownToTheGranularity(string $granularity, int $seconds): void
    {
        $this->timeClaimGranularity = new DateInterval($granularity);

        $before = time();
        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);
        $after = time();

        $payload = $this->signedPayloads[0];
        $issuedAt = $payload[ClaimsEnum::Iat->value] ?? null;

        $this->assertIsInt($issuedAt);
        $this->assertSame($issuedAt, $payload[ClaimsEnum::Nbf->value] ?? null);
        $this->assertSame(0, $issuedAt % $seconds);
        $this->assertLessThanOrEqual($after, $issuedAt);
        $this->assertGreaterThan($before - $seconds, $issuedAt);
    }


    /**
     * The expiry is rounded up from the moment of issuance plus the lifetime, so the credential is valid
     * for at least its lifetime from that moment, and is never issued already expired, however short the
     * lifetime is next to the granularity. Rounding up from the rounded issuance instead would cut the
     * lifetime short by however far into its period issuance fell, which a lifetime as long as the
     * granularity shows on all but the one second of each period which is a boundary.
     */
    #[DataProvider('granularityAndLifetimeProvider')]
    public function testStatesTheExpiryRoundedUpFromTheMomentOfIssuance(
        string $granularity,
        int $granularitySeconds,
        string $lifetime,
        int $lifetimeSeconds,
    ): void {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval($lifetime));
        $this->timeClaimGranularity = new DateInterval($granularity);

        // To the microsecond, since the expiry may not fall short of the lifetime by even a fraction of a
        // second, and the claim, a whole second, may lie within a second of either bound.
        $before = microtime(true);
        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);
        $after = microtime(true);

        $expiresAt = $this->signedPayloads[0][ClaimsEnum::Exp->value] ?? null;

        $this->assertIsInt($expiresAt);
        $this->assertSame(0, $expiresAt % $granularitySeconds);
        $this->assertGreaterThanOrEqual($before + $lifetimeSeconds, $expiresAt);
        $this->assertLessThan($after + $lifetimeSeconds + $granularitySeconds, $expiresAt);
    }


    /**
     * Lifetimes in hours rather than days, which are a fixed number of seconds in any timezone.
     *
     * @return array<string,array{0: string, 1: int, 2: string, 3: int}>
     */
    public static function granularityAndLifetimeProvider(): array
    {
        return [
            'a minute, for a minute' => ['PT1M', 60, 'PT1M', 60],
            'an hour, for an hour' => ['PT1H', 3600, 'PT1H', 3600],
            'a day, for a day' => ['P1D', 86400, 'PT24H', 86400],
            'a week, for a week' => ['P1W', 604800, 'PT168H', 604800],
            'a day, for thirty seconds' => ['P1D', 86400, 'PT30S', 30],
        ];
    }


    /**
     * @return array<string,array{0: string, 1: int}>
     */
    public static function granularityProvider(): array
    {
        return [
            'a minute' => ['PT1M', 60],
            'an hour' => ['PT1H', 3600],
            'a day, the default' => ['P1D', 86400],
            'a week' => ['P1W', 604800],
        ];
    }


    /**
     * The W3C formats state the two moments a second time, as date strings, and those name the rounded
     * moments the claims do rather than the ones they were rounded from.
     */
    public function testTheW3cDateStringsNameTheRoundedMoments(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));
        $this->timeClaimGranularity = new DateInterval('P1D');

        $this->issue(CredentialFormatIdentifiersEnum::JwtVcJson->value);
        $payload = $this->signedPayloads[0];
        $body = (array)($payload[ClaimsEnum::Vc->value] ?? []);

        $this->assertSame(0, (int)($payload[ClaimsEnum::Iat->value] ?? 1) % 86400);
        $this->assertSame(
            $payload[ClaimsEnum::Iat->value] ?? null,
            (new DateTimeImmutable((string)($body[ClaimsEnum::Issuance_Date->value] ?? '')))->getTimestamp(),
        );
        $this->assertSame(
            $payload[ClaimsEnum::Exp->value] ?? null,
            (new DateTimeImmutable((string)($body[ClaimsEnum::Expiration_Date->value] ?? '')))->getTimestamp(),
        );

        $this->setUp();
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));
        $this->timeClaimGranularity = new DateInterval('P1D');

        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);
        $payload = $this->signedPayloads[0];

        $this->assertSame(0, (int)($payload[ClaimsEnum::Iat->value] ?? 1) % 86400);
        $this->assertSame(
            $payload[ClaimsEnum::Iat->value] ?? null,
            (new DateTimeImmutable((string)($payload[ClaimsEnum::ValidFrom->value] ?? '')))->getTimestamp(),
        );
        $this->assertSame(
            $payload[ClaimsEnum::Exp->value] ?? null,
            (new DateTimeImmutable((string)($payload[ClaimsEnum::ValidUntil->value] ?? '')))->getTimestamp(),
        );
    }


    /**
     * A configuration which advertises no proof type issues one credential, to a subject identifier of
     * this issuer's own making, and asks the validator for nothing more than that.
     */
    public function testAProoflessConfigurationIssuesOneUnboundCredential(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::Proofless;

        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
            ClaimsEnum::Vct->value => self::VCT,
        ];
        // A configuration which advertises no proof type resolves no proof, and issues once anyway.
        $this->validatedProofs = [null];

        $this->dispatch();

        $this->assertCount(1, $this->signedPayloads);

        $payload = $this->signedPayloads[0];

        $this->assertSame(self::ISSUER . '/sub/user123', $payload[ClaimsEnum::Sub->value] ?? null);
        // Nothing was proved, so there is no key to confirm the credential is held by.
        $this->assertArrayNotHasKey(ClaimsEnum::Cnf->value, $payload);
    }


    /**
     * The refusal keeps the error code the check that made it chose. Flattening every refusal to
     * `invalid_proof` would tell a wallet whose nonce merely went stale to go looking for a fault in
     * the proof it built, instead of fetching a fresh nonce and retrying.
     */
    public function testAnswersARefusedRequestWithTheErrorCodeTheRefusalCarried(): void
    {
        $this->proofValidationException = new CredentialRequestException(
            'invalid_nonce',
            'c_nonce is invalid or expired.',
        );

        $this->dispatch();

        $this->assertRefusedWith('invalid_nonce', 400);
        $this->assertSame([], $this->jsonResponses);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * Nothing is allocated or signed until every proof in the request has passed.
     *
     * A Status List entry claimed for a credential which is then never issued can not be handed back:
     * the index stays spent, and the list it came from can only be retired once every entry in it has
     * expired. So a request refused on its last proof must leave no trace of its first.
     */
    public function testAllocatesNothingWhenTheRequestIsRefused(): void
    {
        $this->proofValidationException = new CredentialRequestException(
            'invalid_proof',
            'Key proof signature could not be verified.',
        );

        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');

        $this->dispatch();

        $this->assertSame([], $this->signedPayloads);
    }


    public function testCredentialWithMultipleProofs(): void
    {
        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(
                fn(array $data): bool => isset($data['credentials']) && count($data['credentials']) === 2,
            ))
            ->willReturn($this->createMock(JsonResponse::class));

        $this->issue(proofJwts: ['jwt1', 'jwt2']);
    }


    /**
     * Immediate issuance answers 200 and `application/json` (OpenID4VCI 1.0 section 8.3), with `credentials`, an
     * array of objects each holding one `credential` and nothing else. A credential is the string its format is
     * serialized to, not re-encoded (Appendices A.1.1.4 and A.3.4): a JWT in compact serialization for
     * `jwt_vc_json` (A.1.1), and for the SD-JWT formats the issuer-signed JWT followed by each disclosure, each of
     * them ended by a tilde (the compact serialization of RFC 9901 section 4, which HAIP 1.0 section 6.1 asks
     * for). Each JWT verifies with the active signing key, and each disclosure is sent as the string the JWT
     * signed the digest of. The credentials are those of the batch, in order: each bound to its own proof's key,
     * each with its own identifier. The library builds them here, so these are the strings it serialized. Only
     * `vc+sd-jwt` has its `@context` resolved: nothing of a `jwt_vc_json` configuration is read as JSON-LD
     * (Appendix A.1.1.1), nor of a `dc+sd-jwt` one.
     *
     * @param list<array{0: string, 1: mixed}> $disclosed The name and value of each disclosure.
     */
    #[DataProvider('serializedFormatProvider')]
    public function testAnswersEachCredentialAsTheStringItWasSerializedTo(
        CredentialFormatIdentifiersEnum $format,
        string $serialization,
        array $disclosed,
        int $contextResolutions,
    ): void {
        $signingKey = JWKFactory::createECKey('P-256');
        $supportedAlgorithms = new SupportedAlgorithms(new SignatureAlgorithmBag(SignatureAlgorithmEnum::ES256));
        $this->signingKey = new JwkDecorator($signingKey);
        $this->verifiableCredentials = new VerifiableCredentialsService(supportedAlgorithms: $supportedAlgorithms);
        $this->vciContextResolverMock->expects($this->exactly($contextResolutions))->method('resolve')
            ->willReturn([AtContextsEnum::W3OrgNsCredentialsV2->value]);
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'given_name']];
        $this->attributeToClaimPathMap = [['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']]];
        $this->userClaims = ['givenName' => ['John']];
        $this->credentialConfiguration = [ClaimsEnum::Format->value => $format->value] +
        ($format === CredentialFormatIdentifiersEnum::DcSdJwt ? [ClaimsEnum::Vct->value => self::VCT] : []);
        $this->requestData = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => ['jwt1', 'jwt2']],
        ];
        $this->validatedProofs = [
            $this->validatedProof(holderDid: 'did:jwk:first'),
            $this->validatedProof(holderDid: 'did:jwk:second'),
        ];

        $response = $this->dispatch();

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        // Decoded as objects first, where a JSON object and a JSON array stay apart: `credentials` is an array of
        // objects, not an object whose members happen to be numbered.
        $envelope = json_decode((string)$response->getContent(), false, 512, JSON_THROW_ON_ERROR);
        $this->assertInstanceOf(stdClass::class, $envelope);
        $this->assertIsArray($envelope->credentials ?? null);
        /** @psalm-suppress MixedAssignment */
        foreach ($envelope->credentials as $issued) {
            $this->assertInstanceOf(stdClass::class, $issued);
        }

        $body = json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $this->assertIsArray($body);
        $this->assertSame(['credentials'], array_keys($body));
        $this->assertIsArray($body['credentials']);
        $this->assertSame([0, 1], array_keys($body['credentials']));

        $parsedJwsFactory = (new Jws($supportedAlgorithms))->parsedJwsFactory();
        $base64Url = (new VcHelpers())->base64Url();
        $payloads = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($body['credentials'] as $issued) {
            $this->assertIsArray($issued);
            $this->assertSame(['credential'], array_keys($issued));
            $credential = $issued['credential'];
            $this->assertIsString($credential);
            $this->assertMatchesRegularExpression($serialization, $credential);

            $segments = explode('~', $credential);
            $jwt = $parsedJwsFactory->fromToken($segments[0]);
            $jwt->verifyWithKey($signingKey->toPublic()->all());
            $payloads[] = $jwt->getPayload();
            $disclosures = array_slice($segments, 1, -1);
            $this->assertSame(
                $disclosed,
                array_map(
                    static fn(string $disclosure): array => array_slice(
                        (array)json_decode($base64Url->decode($disclosure), true, 512, JSON_THROW_ON_ERROR),
                        1,
                    ),
                    $disclosures,
                ),
            );

            foreach ($disclosures as $disclosure) {
                $this->assertContains(
                    $base64Url->encode(hash('sha256', $disclosure, true)),
                    self::disclosureDigestsIn($jwt->getPayload()),
                );
            }
        }

        $this->assertSame(
            [['kid' => 'did:jwk:first#0'], ['kid' => 'did:jwk:second#0']],
            array_column($payloads, ClaimsEnum::Cnf->value),
        );
        $this->assertCount(2, array_unique(array_column($payloads, ClaimsEnum::Jti->value)));
    }


    /**
     * Every digest the `_sd` arrays of an SD-JWT payload list, at any depth.
     *
     * @return list<mixed>
     */
    protected static function disclosureDigestsIn(array $claims): array
    {
        $digests = [];

        /** @psalm-suppress MixedAssignment */
        foreach ($claims as $name => $value) {
            if ($name === '_sd' && is_array($value)) {
                $digests = [...$digests, ...array_values($value)];
            } elseif (is_array($value)) {
                $digests = [...$digests, ...self::disclosureDigestsIn($value)];
            }
        }

        return $digests;
    }


    /**
     * @return array<string,list<mixed>>
     */
    public static function serializedFormatProvider(): array
    {
        $jwt = '[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+';
        // To the very end (\z): `$` would let a final line break through, after the tilde which ends the string.
        $sdJwt = '/^' . $jwt . '~([A-Za-z0-9_-]+~)+\z/';

        return [
            'jwt_vc_json' => [CredentialFormatIdentifiersEnum::JwtVcJson, '/^' . $jwt . '\z/', [], 0],
            'dc+sd-jwt' => [CredentialFormatIdentifiersEnum::DcSdJwt, $sdJwt, [['given_name', 'John']], 0],
            'vc+sd-jwt' => [CredentialFormatIdentifiersEnum::VcSdJwt, $sdJwt, [['given_name', 'John']], 2],
        ];
    }


    /**
     * The Credential Issuer ignores the parameters of a request it does not recognize (OpenID4VCI 1.0 section 8.2):
     * one no specification defines, and those which named a credential before OpenID4VCI 1.0 (a `format` with a
     * `vct` or a `credential_definition`), sent beside the `credential_configuration_id` which names one now. The
     * credential issued is the one the configuration describes, as for the request without them.
     */
    public function testIgnoresTheParametersOfARequestItDoesNotRecognize(): void
    {
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
            ClaimsEnum::Vct->value => self::VCT,
        ];
        $this->validatedProofs = [$this->validatedProof()];
        $request = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => ['jwt1']],
        ];

        $withoutThem = $this->dispatch($request);
        $withThem = $this->dispatch($request + [
            'x_unrecognized_parameter' => 'a value',
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
            ClaimsEnum::Vct->value => 'urn:example:TypeTheWalletNamed',
            ClaimsEnum::CredentialDefinition->value => [
                ClaimsEnum::Type->value => ['VerifiableCredential', 'TypeTheWalletNamed'],
            ],
        ]);

        $this->assertSame([], $this->errorResponses);
        // Answered as the request without them is: issued, with the credential the factory built.
        foreach ([$withoutThem, $withThem] as $response) {
            $this->assertSame(200, $response->getStatusCode());
            $this->assertSame(
                ['credentials' => [['credential' => 'sd_jwt_token']]],
                json_decode((string)$response->getContent(), true, 512, JSON_THROW_ON_ERROR),
            );
        }
        $this->assertCount(2, $this->signedPayloads);
        $this->assertSame(
            [CredentialFormatIdentifiersEnum::DcSdJwt->value, CredentialFormatIdentifiersEnum::DcSdJwt->value],
            array_column($this->signedWith, 'format'),
        );
        $this->assertSame(self::VCT, $this->signedPayloads[1][ClaimsEnum::Vct->value] ?? null);

        // What identifies a credential, and the moment it was issued, which may have moved on between the two.
        $ofTheRequest = [
            ClaimsEnum::Jti->value => null,
            ClaimsEnum::Iat->value => null,
            ClaimsEnum::Nbf->value => null,
        ];
        $this->assertSame(
            array_diff_key($this->signedPayloads[0], $ofTheRequest),
            array_diff_key($this->signedPayloads[1], $ofTheRequest),
        );
    }


    /**
     * A later request does not revoke what an earlier one issued (OpenID4VCI 1.0 section 14.3, SHOULD NOT): the
     * endpoint, and the status issuer it allocates a Status List entry through for each credential, are given
     * nothing which can change the status of a credential. That is the admin page's and the status API's, through
     * CredentialStatusService, a status updater and the entries' repository. The allocator the status issuer claims
     * an entry through holds that repository, and that claiming one leaves every other as it was is
     * DbStatusIndexAllocatorTest::testLeavesTheEntryOfAnEarlierCredentialOfTheSameSubjectAsItWas'. That a later
     * request is served at all is testIssuesAgainstATokenWhichFollowedAnOfferForEveryRequestItMakes'.
     */
    public function testIsGivenNothingWhichCanChangeTheStatusOfACredential(): void
    {
        $statusChangers = [
            CredentialStatusService::class,
            StatusUpdaterInterface::class,
            StatusListEntryRepository::class,
        ];

        foreach ([CredentialIssuerCredentialController::class, CredentialStatusIssuer::class] as $class) {
            $parameters = (new ReflectionClass($class))->getConstructor()?->getParameters() ?? [];
            $this->assertNotSame([], $parameters, $class);

            foreach ($parameters as $parameter) {
                // Every class a nullable, union or intersection type names.
                $types = preg_split('/[?|&()]/', (string)$parameter->getType(), -1, PREG_SPLIT_NO_EMPTY) ?: [];
                $this->assertNotEmpty($types, $parameter->getName());

                foreach ($types as $type) {
                    foreach ($statusChangers as $statusChanger) {
                        $this->assertFalse(
                            is_a($type, $statusChanger, true),
                            sprintf('%s is given %s $%s.', $class, $type, $parameter->getName()),
                        );
                    }
                }
            }
        }
    }


    /**
     * The identifier is the key revocation is later requested by, so anyone able to guess one could ask
     * for a credential they were never issued to be withdrawn.
     */
    public function testTheCredentialIdentifierIsUnpredictable(): void
    {
        $this->issue(proofJwts: ['jwt1', 'jwt2']);

        $identifiers = array_column($this->signedPayloads, ClaimsEnum::Jti->value);

        $this->assertCount(2, $identifiers);
        $this->assertNotSame($identifiers[0], $identifiers[1]);

        foreach ($identifiers as $identifier) {
            // Still a URI, since the credential parsers enforce that of a `jti`.
            $this->assertMatchesRegularExpression(
                '#^' . preg_quote(self::ISSUER, '#') . '/vc/[0-9a-f]{64}$#',
                (string)$identifier,
            );
        }
    }


    /**
     * A request carrying several proofs is issued several credentials, and each one has to be
     * revocable on its own.
     */
    public function testAllocatesAStatusListEntryForEachIssuedCredential(): void
    {
        $allocatedFor = [];

        $this->credentialStatusIssuerMock->expects($this->exactly(2))
            ->method('issueFor')
            ->willReturnCallback(
                function (
                    string $credentialConfigurationId,
                    string $credentialId,
                ) use (&$allocatedFor): StatusClaim {
                    $allocatedFor[] = $credentialId;

                    return $this->statusClaim(count($allocatedFor));
                },
            );

        $this->issue(proofJwts: ['jwt1', 'jwt2']);

        $this->assertCount(2, $allocatedFor);
        $this->assertNotSame($allocatedFor[0], $allocatedFor[1]);
        // The identifier is minted before allocation, because claiming the index and recording what it
        // was claimed for are one operation.
        $this->assertSame(
            $allocatedFor,
            array_column($this->signedPayloads, ClaimsEnum::Jti->value),
        );
    }


    public function testMergesTheStatusClaimIntoTheCredential(): void
    {
        $this->credentialStatusIssuerMock->method('issueFor')->willReturn($this->statusClaim(7));

        $this->issue();

        $this->assertSame(
            [
                ClaimsEnum::StatusList->value => [
                    ClaimsEnum::Idx->value => 7,
                    ClaimsEnum::Uri->value => self::STATUS_LIST_URI,
                ],
            ],
            $this->signedPayloads[0][ClaimsEnum::Status->value] ?? null,
        );
    }


    /**
     * The Status List specification places the claim at the top level of a JOSE Referenced Token, not
     * inside the credential body of the W3C formats.
     */
    public function testTheStatusClaimIsNotPlacedInsideTheCredentialBody(): void
    {
        $this->credentialStatusIssuerMock->method('issueFor')->willReturn($this->statusClaim());

        $this->issue();

        $this->assertArrayHasKey(ClaimsEnum::Status->value, $this->signedPayloads[0]);
        $this->assertArrayNotHasKey(
            ClaimsEnum::Status->value,
            (array)($this->signedPayloads[0][ClaimsEnum::Vc->value] ?? []),
        );
    }


    public function testCarriesTheStatusClaimInEverySupportedFormat(): void
    {
        foreach (
            [
                CredentialFormatIdentifiersEnum::JwtVcJson->value,
                CredentialFormatIdentifiersEnum::DcSdJwt->value,
                CredentialFormatIdentifiersEnum::VcSdJwt->value,
            ] as $format
        ) {
            $this->setUp();
            $this->credentialStatusIssuerMock->method('issueFor')->willReturn($this->statusClaim());

            $this->issue($format);

            $this->assertArrayHasKey(
                ClaimsEnum::Status->value,
                $this->signedPayloads[0],
                sprintf('Format "%s" was issued without a status claim.', $format),
            );
        }
    }


    /**
     * A configuration which belongs to no pool was never meant to be revocable, and its credentials are
     * issued exactly as before.
     */
    public function testIssuesWithoutAStatusClaimWhenTheConfigurationHasNoPool(): void
    {
        $this->credentialStatusIssuerMock->method('issueFor')->willReturn(null);

        $this->routesMock->expects($this->once())->method('newJsonResponse')
            ->willReturn($this->createMock(JsonResponse::class));

        $this->issue();

        $this->assertArrayNotHasKey(ClaimsEnum::Status->value, $this->signedPayloads[0]);
    }


    /**
     * Issuing anyway would hand out a credential which can never be withdrawn, with nothing on it to
     * say so, which is worse than refusing the request.
     */
    public function testRefusesToIssueWhenAStatusListEntryCanNotBeAllocated(): void
    {
        $this->credentialStatusIssuerMock->method('issueFor')
            ->willThrowException(new StatusListException('no list available'));

        $this->routesMock->expects($this->never())->method('newJsonResponse');
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('server_error', $this->anything(), 500)
            ->willReturn($this->createMock(JsonResponse::class));

        $this->issue();

        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * No lifetime is configured by default, and adding one changes what already issued credentials
     * mean, so nothing expires unless an operator asks for it.
     */
    public function testCredentialsDoNotExpireByDefault(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(null);

        $this->issue();

        $this->assertArrayNotHasKey(ClaimsEnum::Exp->value, $this->signedPayloads[0]);
        $this->assertArrayNotHasKey(
            ClaimsEnum::Expiration_Date->value,
            (array)($this->signedPayloads[0][ClaimsEnum::Vc->value] ?? []),
        );
    }


    public function testAppliesTheConfiguredCredentialLifetime(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));

        $this->issue();

        $payload = $this->signedPayloads[0];

        // The expectation adds the interval the same way issuance does, in the same timezone, rather
        // than assuming 30 days is 30 times 86400 seconds. It is not, on either side of a daylight
        // saving transition, and asserting the arithmetic would make this test fail seasonally.
        $expiresAt = (new DateTimeImmutable('@' . $payload[ClaimsEnum::Iat->value]))
            ->setTimezone(new DateTimeZone(date_default_timezone_get()))
            ->add(new DateInterval('P30D'));

        $this->assertSame($expiresAt->getTimestamp(), $payload[ClaimsEnum::Exp->value] ?? null);

        // Stated in the credential body too, the way the issuance date already is, and naming the
        // same moment as the claim above rather than a second, differently derived one.
        $verifiableCredentialBody = (array)($payload[ClaimsEnum::Vc->value] ?? []);
        $expirationDate = $verifiableCredentialBody[ClaimsEnum::Expiration_Date->value] ?? null;

        $this->assertIsString($expirationDate);
        $this->assertSame(
            $expiresAt->getTimestamp(),
            (new DateTimeImmutable($expirationDate))->getTimestamp(),
        );
    }


    /**
     * The Verifiable Credentials Data Model 2.0 names the end of validity `validUntil`, alongside the
     * `validFrom` this format already emits.
     */
    public function testTheDataModelTwoFormatAlsoStatesTheLifetimeAsValidUntil(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));

        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        $payload = $this->signedPayloads[0];

        $this->assertArrayHasKey(ClaimsEnum::ValidUntil->value, $payload);
        $this->assertArrayHasKey(ClaimsEnum::Exp->value, $payload);
    }


    /**
     * OpenID Fed DCP (Appendix B of DIIP v5) has a credential name the Entity Identifier a verifier
     * resolves the Issuer's Trust Chain from. That identifier only leads anywhere while an Entity
     * Configuration is published at it, which is what the federation switch decides, so with it off
     * nothing is named - in any of the three formats, and in neither vocabulary.
     */
    public function testNamesNoFederationEntityWhileFederationIsOff(): void
    {
        $issuableFormats = [
            CredentialFormatIdentifiersEnum::JwtVcJson,
            CredentialFormatIdentifiersEnum::DcSdJwt,
            CredentialFormatIdentifiersEnum::VcSdJwt,
        ];

        foreach ($issuableFormats as $format) {
            $this->setUp();
            $this->moduleConfigMock->method('getFederationEnabled')->willReturn(false);
            $this->issue($format->value);

            $payload = $this->signedPayloads[0];

            $this->assertArrayNotHasKey(ClaimsEnum::Fed->value, $payload, $format->value);
            $this->assertArrayNotHasKey(ClaimsEnum::Terms_Of_Use->value, $payload, $format->value);
            $this->assertArrayNotHasKey(
                ClaimsEnum::Terms_Of_Use->value,
                (array)($payload[ClaimsEnum::Vc->value] ?? []),
                $format->value,
            );
        }
    }


    /**
     * An SD-JWT VC names its federation in a `fed` claim. The value is the issuer URL and not the `iss`
     * beside it, which here is a DID: a DID has no Entity Configuration to fetch, and bridging that is
     * what the claim is for.
     */
    public function testAnSdJwtVcCarriesTheEntityIdentifierInTheFedClaim(): void
    {
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);

        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);

        $payload = $this->signedPayloads[0];

        $this->assertSame(self::ISSUER, $payload[ClaimsEnum::Fed->value] ?? null);
        $this->assertSame(self::ISSUER_DID, $payload[ClaimsEnum::Iss->value] ?? null);

        // The data model vocabulary belongs to the W3C formats, not to this one.
        $this->assertArrayNotHasKey(ClaimsEnum::Terms_Of_Use->value, $payload);
    }


    /**
     * A W3C VCDM credential names its federation in the data model's own vocabulary: a `termsOfUse`
     * entry of type `OpenIDFederation` whose `policyId` is the Entity Identifier. It sits in the
     * credential body, which for `jwt_vc_json` is the `vc` claim and for `vc+sd-jwt` is the payload.
     */
    public function testAW3cCredentialCarriesTheOpenIdFederationTermsOfUse(): void
    {
        $expectedTermsOfUse = [
            ClaimsEnum::Type->value => TermsOfUseTypesEnum::OpenIdFederation->value,
            ClaimsEnum::Policy_Id->value => self::ISSUER,
        ];

        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->issue(CredentialFormatIdentifiersEnum::JwtVcJson->value);

        $payload = $this->signedPayloads[0];
        $verifiableCredentialBody = (array)($payload[ClaimsEnum::Vc->value] ?? []);

        $this->assertSame(
            $expectedTermsOfUse,
            $verifiableCredentialBody[ClaimsEnum::Terms_Of_Use->value] ?? null,
        );
        $this->assertArrayNotHasKey(ClaimsEnum::Terms_Of_Use->value, $payload);
        $this->assertArrayNotHasKey(ClaimsEnum::Fed->value, $payload);

        $this->setUp();
        $this->moduleConfigMock->method('getFederationEnabled')->willReturn(true);
        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        $payload = $this->signedPayloads[0];

        $this->assertSame($expectedTermsOfUse, $payload[ClaimsEnum::Terms_Of_Use->value] ?? null);
        $this->assertArrayNotHasKey(ClaimsEnum::Fed->value, $payload);
    }


    public function testTheStatusListEntryIsAllocatedWithTheCredentialLifetime(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));
        // Rounded, so that the expiry handed over has to be the one the credential states, not the moment
        // it was rounded from.
        $this->timeClaimGranularity = new DateInterval('P1D');

        $expiresAt = null;
        $this->credentialStatusIssuerMock->method('issueFor')->willReturnCallback(
            function (
                string $credentialConfigurationId,
                string $credentialId,
                string $userIdentifier,
                mixed $configuredExpiresAt,
            ) use (&$expiresAt): StatusClaim {
                $expiresAt = $configuredExpiresAt;

                return $this->statusClaim();
            },
        );

        $this->issue();

        // Otherwise the entry could never be cleaned up, and its list could never be retired.
        $this->assertSame(
            $this->signedPayloads[0][ClaimsEnum::Exp->value] ?? null,
            $expiresAt?->getTimestamp(),
        );
    }


    /**
     * The token authenticated, so this is not an authentication failure: it names an authorization this
     * issuer no longer holds, which is what `invalid_token` says.
     */
    public function testAnswersWithInvalidTokenWhenTheAccessTokenIsNotFound(): void
    {
        $this->accessTokenIsFound = false;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * The resource server refuses an access token which is invalid or revoked with `invalid_token` and 401. The
     * refusal is answered as the client's error response, with the challenges it carries, rather than left to
     * escape to SimpleSAMLphp, which answered it with an HTML page and a 500.
     */
    public function testAnswersTheResourceServerRefusingTheAccessToken(): void
    {
        $refusal = OidcServerException::invalidToken(
            'Access token has been revoked',
            null,
            OidcServerException::buildResourceChallenges(
                AccessTokenTypesEnum::Bearer,
                'invalid_token',
                ['ES256', 'PS256'],
            ),
        );
        $this->accessTokenRefusal = $refusal;

        $response = $this->dispatch();

        $this->assertSame($this->errorResponderResponse, $response);
        $this->assertSame([$refusal], $this->oauthErrors);
        $this->assertAnsweredWithOAuthError('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
    }


    /**
     * A request which carried no access token, or one only in the query string, where the resource server reads
     * none, gets the bare challenge and no body (RFC 6750 section 3.1): no error code tells the wallet its token
     * was refused when it sent none.
     */
    public function testAnswersARequestWithoutAnAccessTokenWithTheBareChallengeAlone(): void
    {
        $refusal = OidcServerException::missingToken('No Bearer access token.');
        $this->accessTokenRefusal = $refusal;

        $response = $this->dispatch();

        $this->assertSame($this->errorResponderResponse, $response);
        $this->assertSame([$refusal], $this->oauthErrors);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame('Bearer', $response->headers->get('WWW-Authenticate'));
        $this->assertSame('', $response->getContent());
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A failure of the OP's own while the token was checked says nothing about the token, so it carries no
     * challenge.
     */
    public function testAnswersAFailureWhileCheckingTheTokenWithoutAChallenge(): void
    {
        $this->accessTokenRefusal = OidcServerException::serverError('The access token could not be checked.');

        $response = $this->dispatch();

        $this->assertAnsweredWithOAuthError('server_error', 500);
        $this->assertFalse($response->headers->has('WWW-Authenticate'));
    }


    /**
     * Any other 401 still carries challenges, both schemes with no error, since HTTP requires one of every 401
     * (RFC 9110 section 15.5.2) and the endpoint takes tokens under both (RFC 9449 section 7.2).
     */
    public function testChallengesAnyOther401WithBothSchemesAndNoError(): void
    {
        $this->accessTokenRefusal = OidcServerException::accessDenied('Denied.');

        $response = $this->dispatch();

        $this->assertAnsweredWithOAuthError('access_denied', 401);
        $this->assertSame('Bearer, DPoP algs="ES256 PS256"', $response->headers->get('WWW-Authenticate'));
    }


    public function testAnswersWithInvalidTokenWhenTheAccessTokenIsRevoked(): void
    {
        $this->accessTokenIsRevoked = true;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * An access token from a plain OIDC flow authenticates its holder perfectly well, and still must
     * not buy a credential: nothing in that flow established which credential the holder is entitled
     * to, so there is nothing for this endpoint to check the request against.
     */
    #[DataProvider('flowTypesWhichCanNotBuyACredentialProvider')]
    public function testRefusesAnAccessTokenNotIssuedForCredentialIssuance(?FlowTypeEnum $flowType): void
    {
        $this->flowType = $flowType;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * @return array<string,array{0: ?\SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum}>
     */
    public static function flowTypesWhichCanNotBuyACredentialProvider(): array
    {
        return [
            'authorization code' => [FlowTypeEnum::OidcAuthorizationCode],
            'implicit' => [FlowTypeEnum::OidcImplicit],
            'refresh token' => [FlowTypeEnum::OidcRefreshToken],
            'no flow type recorded' => [null],
        ];
    }


    /**
     * The token is checked against the URL this issuer publishes for the endpoint, which the `htu` of a DPoP proof
     * has to name.
     */
    public function testChecksTheTokenForThePublishedCredentialEndpoint(): void
    {
        $this->dispatch();

        $this->assertSame([self::CREDENTIAL_ENDPOINT], $this->resourceUrls);
    }


    /**
     * @return array<string,array{0: string}>
     */
    public static function tokenWhichCanNotBuyACredentialProvider(): array
    {
        return [
            'not found' => ['not found'],
            'revoked' => ['revoked'],
            'not issued for credential issuance' => ['not vci'],
            'no issuer state of the generic client' => ['no issuer state'],
            'naming no user' => ['no user'],
            'naming a user who no longer exists' => ['user gone'],
        ];
    }


    /**
     * A token presented under the DPoP scheme which passed the resource server but can not buy a credential is
     * refused under that scheme, the challenge naming the algorithms a proof may be signed with (RFC 9449
     * section 7.1).
     */
    #[DataProvider('tokenWhichCanNotBuyACredentialProvider')]
    public function testRefusesATokenPresentedUnderTheDpopSchemeUnderThatScheme(string $fault): void
    {
        $this->presentedScheme = 'DPoP';
        switch ($fault) {
            case 'not found':
                $this->accessTokenIsFound = false;
                break;
            case 'revoked':
                $this->accessTokenIsRevoked = true;
                break;
            case 'not vci':
                $this->flowType = FlowTypeEnum::OidcAuthorizationCode;
                break;
            case 'no user':
                $this->accessTokenUserIdentifier = null;
                break;
            case 'user gone':
                $this->userEntity = null;
                break;
            default:
                $this->flowType = FlowTypeEnum::VciAuthorizationCode;
                $this->clientIsGeneric = true;
        }

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertSame(
            'DPoP error="invalid_token", algs="ES256 PS256"',
            $response->headers->get('WWW-Authenticate'),
        );
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * The generic client stands in for wallets which are not registered, and gets a token only for a request
     * following an offer, so the issuer state is what its credential request is redeemable against. A token
     * of it carrying none is one this endpoint can not tie back to anything. The token is at fault, not the
     * request, so the refusal is RFC 6750's (OpenID4VCI 1.0 section 8.3.1.1).
     */
    public function testRefusesAnAuthorizationCodeFlowOfTheGenericClientCarryingNoIssuerState(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = null;
        $this->clientIsGeneric = true;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A registered wallet may start the authorization code flow on its own, without an offer, and so without
     * an issuer state: its registration is what allowed the credential scope it was granted.
     */
    public function testIssuesForAnAuthorizationCodeFlowOfARegisteredClientCarryingNoIssuerState(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = null;
        $this->tokenScopes = [new ScopeEntity(self::CONFIGURATION_ID)];

        $this->issue();

        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A token's scopes are all it grants, whichever flow issued it: without an offer, what the client was
     * authorized for; after an offer or with a pre-authorized code, no more than the offer offered. A credential
     * they do not name is refused, however much the client is registered and whatever the offer's issuer state.
     */
    #[DataProvider('tokensOfEveryCredentialFlowProvider')]
    public function testRefusesACredentialTheTokenDoesNotGrant(
        FlowTypeEnum $flowType,
        ?string $issuerState,
        bool $clientIsGeneric,
    ): void {
        $this->flowType = $flowType;
        $this->issuerState = $issuerState;
        $this->clientIsGeneric = $clientIsGeneric;
        $this->tokenScopes = [new ScopeEntity('another_configuration')];

        $response = $this->issue();

        $this->assertRefusedWith('insufficient_scope', 403);
        // RFC 6750 section 3: a token which does not enable the request is answered with a challenge, naming the
        // error under the scheme the token came under, the DPoP one beside it (RFC 9449 section 7.2).
        $this->assertSame(
            'Bearer error="insufficient_scope", DPoP algs="ES256 PS256"',
            $response->headers->get('WWW-Authenticate'),
        );
        $this->assertSame([], $this->signedPayloads);
    }


    public function testRefusesACredentialTheTokenDoesNotGrantUnderTheSchemeItWasPresentedUnder(): void
    {
        $this->presentedScheme = 'DPoP';
        $this->tokenScopes = [new ScopeEntity('another_configuration')];

        $response = $this->issue();

        $this->assertRefusedWith('insufficient_scope', 403);
        $this->assertSame(
            'DPoP error="insufficient_scope", algs="ES256 PS256"',
            $response->headers->get('WWW-Authenticate'),
        );
    }


    /**
     * @return array<string,array{0: \SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum, 1: ?string, 2: bool}>
     */
    public static function tokensOfEveryCredentialFlowProvider(): array
    {
        return [
            'authorization code, a registered client, no offer' => [FlowTypeEnum::VciAuthorizationCode, null, false],
            'authorization code after an offer, a non-registered wallet' => [
                FlowTypeEnum::VciAuthorizationCode,
                'issuer-state-1',
                true,
            ],
            'authorization code after an offer, a registered client' => [
                FlowTypeEnum::VciAuthorizationCode,
                'issuer-state-1',
                false,
            ],
            'pre-authorized code' => [FlowTypeEnum::VciPreAuthorizedCode, null, false],
        ];
    }


    /**
     * Authorization details are kept on the token as they were requested, while its scopes are what the token
     * endpoint left of them for this client. So the credential they name still has to be among the scopes.
     */
    public function testRefusesAnAuthorizationDetailOfARegisteredClientTheTokenDoesNotGrant(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = null;
        $this->authorizationDetails = [$this->authorizationDetail(self::CONFIGURATION_ID)];
        $this->tokenScopes = [];
        $this->requestData = [ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertRefusedWith('insufficient_scope', 403);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A token which followed an offer serves as many credential requests as its lifetime allows, as any other
     * does (OpenID4VCI 1.0 section 14.3). The offer was spent when the code carrying it was exchanged for the
     * token, so this endpoint has nothing left to spend, and a second request is answered as the first was.
     */
    public function testIssuesAgainstATokenWhichFollowedAnOfferForEveryRequestItMakes(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = 'issuer-state-1';
        $this->clientIsGeneric = true;

        $this->issue();
        $this->issue();

        $this->assertCount(2, $this->signedPayloads);
    }


    /**
     * The two parameters name a credential in two different ways, and a request uses one of them.
     * Picking one would mean guessing which credential was meant. One sent as null is sent all the same: each
     * request below would be issued if the member written as null were taken as left out.
     *
     * @param array<string,mixed> $requestData
     */
    #[DataProvider('bothWaysOfNamingTheCredentialProvider')]
    public function testRefusesACredentialConfigurationIdSentTogetherWithACredentialIdentifier(
        array $requestData,
        bool $withAuthorizationDetails,
    ): void {
        $authorizationDetails = [$this->authorizationDetail(self::CONFIGURATION_ID)];
        $this->authorizationDetails = $withAuthorizationDetails ? $authorizationDetails : null;
        $this->requestData = $requestData;
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        // For naming it both ways, not for a member which names nothing.
        $this->assertStringContainsString('together', $this->errorResponses[0]['description']);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * @return array<string,array{0: array<string,mixed>, 1: bool}>
     */
    public static function bothWaysOfNamingTheCredentialProvider(): array
    {
        return [
            'both with a value' => [
                [
                    ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
                    ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID,
                ],
                false,
            ],
            'a credential identifier of null' => [
                [
                    ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
                    ClaimsEnum::CredentialIdentifier->value => null,
                ],
                false,
            ],
            'a credential configuration id of null' => [
                [
                    ClaimsEnum::CredentialConfigurationId->value => null,
                    ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID,
                ],
                true,
            ],
        ];
    }


    /**
     * A flow which used `authorization_details` authorized particular credentials, so the request has
     * to say which of them it is redeeming.
     */
    public function testRefusesWhenAuthorizationDetailsRequireACredentialIdentifierAndNoneWasSent(): void
    {
        $this->authorizationDetails = [$this->authorizationDetail(self::CONFIGURATION_ID)];
        $this->requestData = [];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * The credential identifier has to name something the flow actually authorized. Otherwise the
     * request itself would decide what is issued, and `authorization_details` would constrain nothing.
     */
    public function testRefusesACredentialIdentifierNoAuthorizationDetailAuthorized(): void
    {
        $this->authorizationDetails = [$this->authorizationDetail('another_configuration')];
        $this->requestData = [ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID];

        $this->dispatch();

        $this->assertRefusedWith('unknown_credential_identifier', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A credential identifier names one the token response issued with `authorization_details`. A flow
     * which used none was issued none, so the identifier is unknown, rather than ignored while the
     * credential is resolved some other way: here it names a configuration the token grants, which
     * `credential_configuration_id` would have been issued.
     */
    public function testRefusesACredentialIdentifierForAFlowWhichWasIssuedNone(): void
    {
        $this->authorizationDetails = null;
        $this->requestData = [ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertRefusedWith('unknown_credential_identifier', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A credential identifier which is not a non-empty string names nothing at all, and is a malformed request
     * rather than an unknown identifier, with or without `authorization_details`.
     */
    #[DataProvider('credentialIdentifierWhichIsNotANonEmptyStringProvider')]
    public function testRefusesACredentialIdentifierWhichIsNotANonEmptyString(
        mixed $credentialIdentifier,
        bool $withAuthorizationDetails,
    ): void {
        $authorizationDetails = [$this->authorizationDetail(self::CONFIGURATION_ID)];
        $this->authorizationDetails = $withAuthorizationDetails ? $authorizationDetails : null;
        $this->requestData = [ClaimsEnum::CredentialIdentifier->value => $credentialIdentifier];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * @return array<string,array{0: mixed, 1: bool}>
     */
    public static function credentialIdentifierWhichIsNotANonEmptyStringProvider(): array
    {
        return [
            'a list, no authorization details' => [[self::CONFIGURATION_ID], false],
            'a list, with authorization details' => [[self::CONFIGURATION_ID], true],
            'null, no authorization details' => [null, false],
            'null, with authorization details' => [null, true],
            'empty, with authorization details' => ['', true],
        ];
    }


    /**
     * An authorization detail this endpoint can not read is skipped rather than taken as a refusal: a
     * flow may authorize several credentials, and one entry which makes no sense says nothing about
     * the others.
     */
    public function testIgnoresUnusableAuthorizationDetailsAndStillMatchesALaterOne(): void
    {
        $this->authorizationDetails = [
            'not an authorization detail at all',
            [
                ClaimsEnum::Type->value => 'something_else',
                ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            ],
            [ClaimsEnum::Type->value => 'openid_credential'],
            [
                ClaimsEnum::Type->value => 'openid_credential',
                ClaimsEnum::CredentialConfigurationId->value => ['not a string'],
            ],
            $this->authorizationDetail(self::CONFIGURATION_ID),
        ];
        $this->requestData = [ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A request names its credential by `credential_identifier` or by `credential_configuration_id` (OpenID4VCI
     * 1.0 section 8.2). What came before 1.0, a `format` with a credential definition type or a `vct`, names
     * nothing to this issuer, so a request which sends only that is as malformed as one sending nothing; so is a
     * `credential_configuration_id` which is not a non-empty string.
     *
     * @param array<string,mixed> $requestData
     */
    #[DataProvider('requestNamingNoCredentialProvider')]
    public function testRefusesARequestWhichNamesNoCredential(array $requestData): void
    {
        $this->requestData = $requestData;
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * @return array<string,array{0: array<string,mixed>}>
     */
    public static function requestNamingNoCredentialProvider(): array
    {
        return [
            'nothing' => [[]],
            'a format and a credential definition type' => [
                [
                    ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
                    ClaimsEnum::CredentialDefinition->value => [
                        ClaimsEnum::Type->value => ['VerifiableCredential', self::CONFIGURATION_ID],
                    ],
                ],
            ],
            'a format and a vct' => [
                [
                    ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
                    ClaimsEnum::Vct->value => self::CONFIGURATION_ID,
                ],
            ],
            'a format alone' => [[ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value]],
            'a format this issuer does not issue' => [[ClaimsEnum::Format->value => 'mso_mdoc']],
            'a credential configuration id of null' => [[ClaimsEnum::CredentialConfigurationId->value => null]],
            'an empty credential configuration id' => [[ClaimsEnum::CredentialConfigurationId->value => '']],
            'a credential configuration id which is a list' => [
                [ClaimsEnum::CredentialConfigurationId->value => [self::CONFIGURATION_ID]],
            ],
        ];
    }


    /**
     * An SD-JWT VC states the `vct` its configuration advertises (OpenID4VCI 1.0 Appendix A.3.2), not the
     * configuration id, and a `vct` written as a URI is issued without a word in the log.
     */
    public function testAnSdJwtVcStatesTheVctItsConfigurationAdvertises(): void
    {
        $logged = $this->captureLog();

        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);

        $this->assertSame([], $this->errorResponses);
        $this->assertSame(self::VCT, $this->signedPayloads[0][ClaimsEnum::Vct->value] ?? null);
        $this->assertSame([], $this->logLinesOfLevel($logged, 'warning'));
    }


    /**
     * A `vct` which is not a URI may still be a collision-resistant name, so the credential is issued with it,
     * and the log says it may not be one (decision D25).
     */
    public function testIssuesAVctWhichIsNotAUriAndWarnsThatItMayCollide(): void
    {
        $logged = $this->captureLog();
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
            ClaimsEnum::Vct->value => 'TestCredentialType',
        ];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertSame('TestCredentialType', $this->signedPayloads[0][ClaimsEnum::Vct->value] ?? null);
        $this->assertSame(
            [[
                'The vct of a credential configuration is not a URI, so it may not be a collision-resistant ' .
                'name: a verifier could take another issuer\'s credentials of the same vct for this type.',
                ['credentialConfigurationId' => self::CONFIGURATION_ID, 'vct' => 'TestCredentialType'],
            ]],
            $this->logLinesOfLevel($logged, 'warning'),
        );
    }


    /**
     * The `vct` is what a verifier reads the type of an SD-JWT VC by, so a configuration without one is this
     * issuer's own misconfiguration, answered as such before anything is allocated or signed.
     */
    #[DataProvider('missingVctProvider')]
    public function testFailsWhenTheResolvedSdJwtVcConfigurationStatesNoVct(array $vct): void
    {
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
        ] + $vct;
        $this->validatedProofs = [$this->validatedProof()];
        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');

        $this->dispatch();

        $this->assertAnsweredWithOAuthError('server_error', 500);
        $this->assertSame([], $this->signedPayloads);
    }


    public static function missingVctProvider(): array
    {
        return [
            'no vct' => [[]],
            'an empty vct' => [[ClaimsEnum::Vct->value => '']],
            'a vct which is not a string' => [[ClaimsEnum::Vct->value => ['urn:example:Test']]],
        ];
    }


    public function testRefusesAnUnknownCredentialConfiguration(): void
    {
        $this->credentialConfiguration = null;

        $response = $this->dispatch();

        $this->assertRefusedWith('unknown_credential_configuration', 400);
        // A request refused for what it asks, not for its token, carries no challenge.
        $this->assertFalse($response->headers->has('WWW-Authenticate'));
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * An error description says what is wrong without repeating what the request sent, which is the wallet's
     * own text and may hold anything.
     */
    public function testDoesNotNameAnUnknownCredentialConfigurationBack(): void
    {
        $this->credentialConfiguration = null;
        $this->requestData = [ClaimsEnum::CredentialConfigurationId->value => 'Wanted"Configuration'];

        $this->dispatch();

        $this->assertRefusedWith('unknown_credential_configuration', 400);
        $this->assertStringNotContainsString('Wanted', $this->errorResponses[0]['description']);
    }


    /**
     * Format is what decides how a credential is built, so a configuration without one is this
     * issuer's own misconfiguration rather than a bad request, and is answered as such.
     */
    public function testFailsWhenTheResolvedConfigurationStatesNoFormat(): void
    {
        $this->credentialConfiguration = [];

        $this->dispatch();

        $this->assertAnsweredWithOAuthError('server_error', 500);
    }


    /**
     * A configured format with no branch which builds it must not reach the response: an empty
     * credential would be indistinguishable from an issued one.
     */
    public function testFailsWhenTheResolvedFormatHasNoIssuanceBranch(): void
    {
        $this->credentialConfiguration = [ClaimsEnum::Format->value => 'mso_mdoc'];
        $this->validatedProofs = [$this->validatedProof()];

        $this->expectException(OpenIdException::class);

        $this->dispatch();
    }


    /**
     * The credential is about a user, so an access token which names none, or one who no longer exists, can
     * not buy one, and that is the token's fault: RFC 6750's `invalid_token` (OpenID4VCI 1.0 section 8.3.1.1).
     */
    public function testRefusesAnAccessTokenWhichNamesNoUser(): void
    {
        $this->accessTokenUserIdentifier = null;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    public function testRefusesAnAccessTokenWhoseUserNoLongerExists(): void
    {
        $this->userEntity = null;

        $response = $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertChallengesTheRefusedToken($response);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * The user is checked with the rest of the token, before the request: a wallet told to mend its request
     * first would mend it only to learn that its token buys nothing.
     */
    public function testRefusesATokenWithoutAUserBeforeLookingAtTheRequest(): void
    {
        $this->userEntity = null;
        $this->requestData = [];

        $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
    }


    /**
     * The mapping is what puts a user's attributes into a credential, and the claim path it names is
     * where they land - nested, when that is what it says.
     */
    public function testMapsAUserAttributeToTheClaimPathItNames(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'given_name']];
        $this->attributeToClaimPathMap = [
            ['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']],
        ];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue();

        // A single valued attribute is stated as the value itself rather than as a list of one.
        $this->assertSame('John', $this->credentialSubjectOfFirstCredential()['given_name'] ?? null);
    }


    public function testKeepsAMultiValuedAttributeAsAList(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'affiliation']];
        $this->attributeToClaimPathMap = [
            ['eduPersonAffiliation' => [ClaimsEnum::Credential_Subject->value, 'affiliation']],
        ];
        $this->userClaims = ['eduPersonAffiliation' => ['member', 'staff']];

        $this->issue();

        $this->assertSame(
            ['member', 'staff'],
            $this->credentialSubjectOfFirstCredential()['affiliation'] ?? null,
        );
    }


    /**
     * A mapping entry this endpoint can not read is skipped and the rest of the mapping still applies.
     * Failing the request instead would let one malformed line in a configuration file stop a
     * deployment issuing anything at all.
     *
     * @param mixed $mapEntry
     */
    #[DataProvider('unreadableMapEntryProvider')]
    public function testSkipsAMappingEntryItCanNotRead(mixed $mapEntry): void
    {
        $this->validClaimPaths = [
            [ClaimsEnum::Credential_Subject->value, 'given_name'],
            [ClaimsEnum::Credential_Subject->value, 'family_name'],
        ];
        $this->attributeToClaimPathMap = [
            $mapEntry,
            ['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']],
        ];
        $this->userClaims = ['givenName' => ['John'], 'sn' => ['Doe']];

        $this->issue();

        $credentialSubject = $this->credentialSubjectOfFirstCredential();

        $this->assertSame('John', $credentialSubject['given_name'] ?? null);
        $this->assertArrayNotHasKey('family_name', $credentialSubject);
    }


    /**
     * @return array<string,array{0: mixed}>
     */
    public static function unreadableMapEntryProvider(): array
    {
        return [
            'entry is not an array' => ['sn'],
            'attribute name is not a string' => [[[ClaimsEnum::Credential_Subject->value, 'family_name']]],
            'claim path is not an array' => [['sn' => 'credentialSubject.family_name']],
        ];
    }


    /**
     * The credential configuration says which claim paths its credentials may carry. A mapping which
     * names another one is not a way to add a claim the configuration never advertised.
     */
    public function testSkipsAnAttributeMappedToAClaimPathTheConfigurationDoesNotAllow(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'given_name']];
        $this->attributeToClaimPathMap = [
            ['sn' => [ClaimsEnum::Credential_Subject->value, 'family_name']],
        ];
        $this->userClaims = ['sn' => ['Doe']];

        $this->issue();

        $this->assertArrayNotHasKey('family_name', $this->credentialSubjectOfFirstCredential());
    }


    /**
     * A mapping describes what to do with an attribute the user has; one they do not have contributes
     * no claim, rather than an empty one.
     */
    public function testSkipsAnAttributeTheUserDoesNotHave(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'given_name']];
        $this->attributeToClaimPathMap = [
            ['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']],
        ];
        $this->userClaims = [];

        $this->issue();

        $this->assertArrayNotHasKey('given_name', $this->credentialSubjectOfFirstCredential());
    }


    /**
     * A claim the configuration advertises as mandatory is one the issuer always includes (OpenID4VCI 1.0
     * Appendix B.2), so a user without the attribute it is mapped from is refused with `credential_request_denied`
     * (section 8.3.1.2) rather than issued a credential a wallet would reject; refused for the whole request,
     * before anything is allocated or signed for any of its credentials. The log names the claim, not the user's
     * attributes.
     */
    #[DataProvider('mandatoryClaimFormatProvider')]
    public function testRefusesAUserWithoutTheAttributeOfAMandatoryClaim(string $format, array $claimPath): void
    {
        $logged = $this->captureLog();
        $this->validClaimPaths = [$claimPath, ['family_name']];
        $this->mandatoryClaimPaths = [$claimPath];
        $this->attributeToClaimPathMap = [['givenName' => $claimPath], ['sn' => ['family_name']]];
        $this->userClaims = ['sn' => ['Doe']];
        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');

        $this->issue($format, ['jwt1', 'jwt2']);

        $this->assertRefusedWith('credential_request_denied', 400);
        $this->assertSame([], $this->signedPayloads);
        $this->assertContains(
            [
                'Credential request denied: the user lacks the attribute of a claim the credential configuration ' .
                'marks as mandatory.',
                ['credentialConfigurationId' => self::CONFIGURATION_ID, 'claimPaths' => [$claimPath]],
            ],
            $this->logLinesOfLevel($logged, 'warning'),
        );
    }


    public static function mandatoryClaimFormatProvider(): array
    {
        $inCredentialSubject = [ClaimsEnum::Credential_Subject->value, 'given_name'];

        return [
            'jwt_vc_json' => [CredentialFormatIdentifiersEnum::JwtVcJson->value, $inCredentialSubject],
            'dc+sd-jwt' => [CredentialFormatIdentifiersEnum::DcSdJwt->value, ['given_name']],
            'vc+sd-jwt' => [CredentialFormatIdentifiersEnum::VcSdJwt->value, $inCredentialSubject],
        ];
    }


    public function testIssuesToAUserWithTheAttributeOfEveryMandatoryClaim(): void
    {
        $claimPath = [ClaimsEnum::Credential_Subject->value, 'given_name'];
        $this->validClaimPaths = [$claimPath];
        $this->mandatoryClaimPaths = [$claimPath];
        $this->attributeToClaimPathMap = [['givenName' => $claimPath]];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertSame('John', $this->credentialSubjectOfFirstCredential()['given_name'] ?? null);
    }


    /**
     * A claim may be mapped from more than one attribute, and is in the credential when any of them is.
     */
    public function testIssuesAMandatoryClaimFromWhicheverAttributeTheUserHas(): void
    {
        $claimPath = [ClaimsEnum::Credential_Subject->value, 'name'];
        $this->validClaimPaths = [$claimPath];
        $this->mandatoryClaimPaths = [$claimPath];
        $this->attributeToClaimPathMap = [['displayName' => $claimPath], ['cn' => $claimPath]];
        $this->userClaims = ['cn' => ['John Doe']];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertSame('John Doe', $this->credentialSubjectOfFirstCredential()['name'] ?? null);
    }


    /**
     * A mandatory claim no attribute is mapped to is not the user's to lack: what the issuer writes itself, as
     * `credentialSubject.id`, is in the credential whatever the user has.
     */
    public function testDoesNotJudgeAMandatoryClaimNoAttributeIsMappedTo(): void
    {
        $this->mandatoryClaimPaths = [[ClaimsEnum::Credential_Subject->value, ClaimsEnum::Id->value]];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A claim the configuration does not mark as mandatory is left out when the user lacks its attribute, as
     * before (testSkipsAnAttributeTheUserDoesNotHave), whatever else is mandatory.
     */
    public function testLeavesOutAClaimWhichIsNotMandatoryWhenTheUserLacksItsAttribute(): void
    {
        $givenName = [ClaimsEnum::Credential_Subject->value, 'given_name'];
        $familyName = [ClaimsEnum::Credential_Subject->value, 'family_name'];
        $this->validClaimPaths = [$givenName, $familyName];
        $this->mandatoryClaimPaths = [$givenName];
        $this->attributeToClaimPathMap = [['givenName' => $givenName], ['sn' => $familyName]];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertArrayNotHasKey('family_name', $this->credentialSubjectOfFirstCredential());
    }


    /**
     * A configuration which could not be published as it stands is not issued under, though a token issued before
     * it changed may still name it: the Credential Endpoint asks ModuleConfig for its fault too, and answers one as
     * this issuer's own misconfiguration, before anything is allocated or signed.
     */
    public function testRefusesToIssueUnderAConfigurationWhichCanNotBeIssuedAsItStands(): void
    {
        $logged = $this->captureLog();
        $this->configurationFault = 'Verifiable Credential configuration [test_id] has no credential_definition.type.';
        $this->validatedProofs = [$this->validatedProof()];
        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');

        $this->dispatch();

        $this->assertAnsweredWithOAuthError('server_error', 500);
        $this->assertSame([], $this->signedPayloads);
        $this->assertSame(
            [[
                'CredentialIssuerCredentialController::credential: The credential configuration can not be issued ' .
                'as it stands.',
                ['credentialConfigurationId' => self::CONFIGURATION_ID, 'fault' => $this->configurationFault],
            ]],
            $this->logLinesOfLevel($logged, 'error'),
        );
    }


    /**
     * The data model 2.0 SD-JWT roots a claim whose parent path does not name credentialSubject there, so a mandatory
     * claim is compared with where a mapping puts its attribute in the credential, not with the path as written:
     * a mapping to ['name'] gives ['credentialSubject', 'name'], and the other way round. (Found by review.)
     */
    #[DataProvider('vcSdJwtRootedClaimProvider')]
    public function testComparesAMandatoryClaimWithWhereTheFormatPutsTheMappedAttribute(
        array $mandatoryClaimPath,
        array $mappedClaimPath,
    ): void {
        $this->validClaimPaths = [['name'], [ClaimsEnum::Credential_Subject->value, 'name']];
        $this->mandatoryClaimPaths = [$mandatoryClaimPath];
        $this->attributeToClaimPathMap = [['displayName' => $mappedClaimPath]];
        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');

        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        $this->assertRefusedWith('credential_request_denied', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    public static function vcSdJwtRootedClaimProvider(): array
    {
        $rooted = [ClaimsEnum::Credential_Subject->value, 'name'];

        return [
            'mandatory under credentialSubject, mapped without it' => [$rooted, ['name']],
            'mandatory without credentialSubject, mapped under it' => [['name'], $rooted],
        ];
    }


    /**
     * A jwt_vc_json body keeps only the credentialSubject member of what the mapping wrote, so a mandatory claim
     * outside it is one no attribute can give, and is not judged (the configuration overview marks the mapping).
     */
    public function testDoesNotJudgeAMandatoryClaimTheFormatCanNotCarry(): void
    {
        $this->validClaimPaths = [['name']];
        $this->mandatoryClaimPaths = [['name']];
        $this->attributeToClaimPathMap = [['displayName' => ['name']]];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A value written inside a mandatory claim brings it into being: the mapping of a locality writes the address
     * object it sits in, so a user without the address attribute is issued a credential which has the address all
     * the same, rather than refused for lacking it. (Found by review.)
     */
    public function testCountsAMandatoryClaimAValueWrittenInsideItBringsIntoBeing(): void
    {
        $address = [ClaimsEnum::Credential_Subject->value, 'address'];
        $locality = [ClaimsEnum::Credential_Subject->value, 'address', 'locality'];
        $this->validClaimPaths = [$address, $locality];
        $this->mandatoryClaimPaths = [$address];
        $this->attributeToClaimPathMap = [['postalAddress' => $address], ['l' => $locality]];
        $this->userClaims = ['l' => ['Zagreb']];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertSame(
            ['locality' => 'Zagreb'],
            $this->credentialSubjectOfFirstCredential()['address'] ?? null,
        );
    }


    /**
     * The inverse: a mandatory claim held by an object another mapping gives is in the credential, so a user who
     * lacks the attribute mapped to the claim itself is not refused for it. (Found by review.)
     */
    public function testCountsAMandatoryClaimAnObjectWrittenAroundItHolds(): void
    {
        $address = [ClaimsEnum::Credential_Subject->value, 'address'];
        $locality = [ClaimsEnum::Credential_Subject->value, 'address', 'locality'];
        $this->validClaimPaths = [$address, $locality];
        $this->mandatoryClaimPaths = [$locality];
        $this->attributeToClaimPathMap = [['postalAddress' => $address], ['l' => $locality]];
        $this->userClaims = ['postalAddress' => ['locality' => 'Zagreb', 'country' => 'HR']];

        $this->issue();

        $this->assertSame([], $this->errorResponses);
        $this->assertSame(
            ['locality' => 'Zagreb', 'country' => 'HR'],
            $this->credentialSubjectOfFirstCredential()['address'] ?? null,
        );
    }


    /**
     * The claims a mandatory pointer addresses have to be in what was written, element by element: an object
     * without the claim, or a list none of whose elements has it, leaves it missing.
     */
    #[DataProvider('writtenWithoutTheMandatoryClaimProvider')]
    public function testRefusesWhenWhatWasWrittenDoesNotHoldTheMandatoryClaim(array $mandatoryPath, mixed $value): void
    {
        $holder = [ClaimsEnum::Credential_Subject->value, 'address'];
        $this->validClaimPaths = [$holder, [ClaimsEnum::Credential_Subject->value, 'address', 'locality']];
        $this->mandatoryClaimPaths = [$mandatoryPath];
        $this->attributeToClaimPathMap = [
            ['postalAddress' => $holder],
            ['l' => [ClaimsEnum::Credential_Subject->value, 'address', 'locality']],
        ];
        $this->userClaims = ['postalAddress' => $value];

        $this->issue();

        $this->assertRefusedWith('credential_request_denied', 400);
    }


    /**
     * What a mapping wrote is recorded where the format puts it, as the mandatory claim is: for the data model 2.0
     * SD-JWT a value mapped to ['name'] lands at ['credentialSubject', 'name'], and so gives a mandatory claim there
     * which another, absent attribute was mapped to.
     */
    public function testCountsAMandatoryClaimAnotherMappingGivesWhereTheFormatPutsIt(): void
    {
        $rooted = [ClaimsEnum::Credential_Subject->value, 'name'];
        $this->validClaimPaths = [['name'], $rooted];
        $this->mandatoryClaimPaths = [$rooted];
        $this->attributeToClaimPathMap = [['displayName' => $rooted], ['cn' => ['name']]];
        $this->userClaims = ['cn' => ['John Doe']];

        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A string component selects an object member, never an array element (OpenID4VCI 1.0 Appendix C.1.1), so a
     * mandatory claim named '0' is not given by a list another mapping wrote in its parent's place, though PHP would
     * find the list's first element under that key. (Found by review.)
     */
    public function testDoesNotTakeAListElementForAMandatoryMemberNamedLikeAnIndex(): void
    {
        $address = [ClaimsEnum::Credential_Subject->value, 'address'];
        $first = [ClaimsEnum::Credential_Subject->value, 'address', '0'];
        $this->validClaimPaths = [$address, $first];
        $this->mandatoryClaimPaths = [$first];
        $this->attributeToClaimPathMap = [['postalAddress' => $address], ['l' => $first]];
        $this->userClaims = ['postalAddress' => ['Zagreb', 'HR']];

        $this->issue();

        $this->assertRefusedWith('credential_request_denied', 400);
    }


    public static function writtenWithoutTheMandatoryClaimProvider(): array
    {
        $locality = [ClaimsEnum::Credential_Subject->value, 'address', 'locality'];

        return [
            'a string where an object is needed' => [$locality, 'Zagreb'],
            'an object without the claim' => [$locality, ['country' => 'HR', 'region' => 'Grad Zagreb']],
        ];
    }


    /**
     * Records what the endpoint logs at every level, as [message, context] lines keyed by level.
     *
     * @return \ArrayObject<string,list<array{0: string, 1: array}>>
     */
    protected function captureLog(): ArrayObject
    {
        $logged = new ArrayObject();
        foreach (['debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency'] as $level) {
            $this->loggerServiceMock->method($level)->willReturnCallback(
                function (string|Stringable $message, array $context = []) use ($logged, $level): void {
                    $lines = $logged[$level] ?? [];
                    $lines[] = [(string)$message, $context];
                    $logged[$level] = $lines;
                },
            );
        }

        return $logged;
    }


    /**
     * @param \ArrayObject<string,list<array{0: string, 1: array}>> $logged
     * @return list<array{0: string, 1: array}>
     */
    protected function logLinesOfLevel(ArrayObject $logged, string $level): array
    {
        return $logged[$level] ?? [];
    }


    /**
     * The SD-JWT formats carry the user's attributes as disclosures rather than in the credential body,
     * so what the mapping produced has to reach the bag the credential is built with.
     */
    public function testAddsEachMappedAttributeToTheDisclosureBag(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value, 'given_name']];
        $this->attributeToClaimPathMap = [
            ['givenName' => [ClaimsEnum::Credential_Subject->value, 'given_name']],
        ];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);

        $this->assertCount(1, $this->disclosureBags);

        // The bag keys its disclosures by salt, which is not what is under test here.
        $disclosures = array_values($this->disclosureBags[0]->all());

        $this->assertCount(1, $disclosures);
        // The claim name is the last segment of the path, and the disclosure sits at what is left.
        $this->assertSame('given_name', $disclosures[0]->getName());
        $this->assertSame('John', $disclosures[0]->getValue());
        $this->assertSame([ClaimsEnum::Credential_Subject->value], $disclosures[0]->getPath());
    }


    /**
     * The Data Model 2.0 format states a subject's claims under `credentialSubject`, so a mapping whose
     * path does not already start there is placed under it - not at the top level, where a verifier
     * would not look for it.
     */
    public function testPlacesADisclosureUnderCredentialSubjectForTheDataModelTwoFormat(): void
    {
        $this->validClaimPaths = [['given_name']];
        $this->attributeToClaimPathMap = [['givenName' => ['given_name']]];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue(CredentialFormatIdentifiersEnum::VcSdJwt->value);

        // The bag keys its disclosures by salt, which is not what is under test here.
        $disclosures = array_values($this->disclosureBags[0]->all());

        $this->assertCount(1, $disclosures);
        $this->assertSame('given_name', $disclosures[0]->getName());
        $this->assertSame([ClaimsEnum::Credential_Subject->value], $disclosures[0]->getPath());
    }


    /**
     * A path with nothing in it names no claim to disclose, and is skipped rather than allowed to fail
     * the whole request.
     */
    public function testSkipsADisclosureWhosePathNamesNoClaim(): void
    {
        $this->validClaimPaths = [[]];
        $this->attributeToClaimPathMap = [['givenName' => []]];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue(CredentialFormatIdentifiersEnum::DcSdJwt->value);

        $this->assertSame([], $this->disclosureBags[0]->all());
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * The subject identifier is stated whatever else was written where it belongs: a mapping which put
     * a scalar there loses its value rather than the credential losing its `id`.
     */
    public function testTheSubjectIdentifierSurvivesAMappingWhichWroteAScalarOverIt(): void
    {
        $this->validClaimPaths = [[ClaimsEnum::Credential_Subject->value]];
        $this->attributeToClaimPathMap = [['givenName' => [ClaimsEnum::Credential_Subject->value]]];
        $this->userClaims = ['givenName' => ['John']];

        $this->issue();

        $this->assertSame(
            [ClaimsEnum::Id->value => self::HOLDER_DID],
            $this->credentialSubjectOfFirstCredential(),
        );
    }


    /**
     * Recorded after the fact, and with the identity credentials were actually signed under rather than
     * what configuration said before any of them was.
     */
    public function testRecordsTheIssuerIdentityCredentialsWereIssuedUnder(): void
    {
        $recorded = [];

        $this->vciIssuerIdentityRepositoryMock->expects($this->once())->method('recordUsage')
            ->willReturnCallback(function (VciIssuerIdentity $issuerIdentity) use (&$recorded): void {
                $recorded[] = $issuerIdentity;
            });

        $this->issue();

        $this->assertCount(1, $recorded);
        $this->assertSame(self::ISSUER_DID, $recorded[0]->getIssuer());
    }


    /**
     * Recording is a diagnostic: it is what later lets an identity change be reported rather than
     * discovered by whoever fails to verify an older credential. The credential is signed and valid
     * whether or not it was written, so failing here would trade a real credential for a note about
     * one.
     */
    public function testStillIssuesWhenTheIssuerIdentityCouldNotBeRecorded(): void
    {
        $this->vciIssuerIdentityRepositoryMock->method('recordUsage')
            ->willThrowException(new RuntimeException('Could not write to the database.'));

        $this->issue();

        $this->assertCount(1, $this->signedPayloads);
        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->jsonResponses);
    }


    /**
     * An identity nothing was signed under obliges this deployment to nothing, so a request which
     * issued no credential records none.
     */
    public function testRecordsNoIssuerIdentityWhenNothingWasIssued(): void
    {
        $this->vciIssuerIdentityRepositoryMock->expects($this->never())->method('recordUsage');
        $this->validatedProofs = [];

        $this->dispatch();

        $this->assertSame([], $this->signedPayloads);
        $this->assertSame([['credentials' => []]], $this->jsonResponses);
    }


    /**
     * @return array<string,mixed>
     */
    protected function authorizationDetail(string $credentialConfigurationId): array
    {
        return [
            ClaimsEnum::Type->value => 'openid_credential',
            ClaimsEnum::CredentialConfigurationId->value => $credentialConfigurationId,
        ];
    }
}
