<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Codebooks\VciIssuerIdentifierModeEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerCredentialController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\IssuerStateEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusIssuer;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentifier;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\VciIssuerIdentity;
use SimpleSAML\Module\oidc\VerifiableCredentials\VciIssuerIdentityResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Exceptions\OpenIdException;
use SimpleSAML\OpenID\Helpers as VcHelpers;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\SdJwt\DisclosureBag;
use SimpleSAML\OpenID\SdJwt\Factories\DisclosureBagFactory;
use SimpleSAML\OpenID\SdJwt\Factories\DisclosureFactory;
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
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

#[AllowMockObjectsWithoutExpectations]
class CredentialIssuerCredentialControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'test_id';

    protected const string ISSUER = 'https://issuer.com';

    protected const string ISSUER_DID = 'did:jwk:test';

    protected const string STATUS_LIST_URI = 'https://issuer.com/module.php/oidc/statuslist/list-1';

    protected const string HOLDER_DID = 'did:jwk:holder';


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

    protected MockObject $issuerStateRepositoryMock;

    protected MockObject $openId4VciProofValidatorMock;

    protected MockObject $vciContextResolverMock;

    protected MockObject $credentialStatusIssuerMock;

    protected Helpers $helpers;

    /** @var array<array<string,mixed>> Payloads handed to whichever credential factory was used. */
    protected array $signedPayloads = [];

    /** @var array<array{key: mixed, algorithm: mixed}> What each of those payloads was signed with. */
    protected array $signedWith = [];

    protected MockObject $vciSignatureKeyPairMock;

    protected MockObject $vciPrivateKeyMock;

    protected VciCredentialBindingPolicyEnum $bindingPolicy;

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

    protected bool $accessTokenIsFound = true;

    protected bool $accessTokenIsRevoked = false;

    protected ?string $accessTokenUserIdentifier = null;

    /** @var ?array<array-key,mixed> */
    protected ?array $authorizationDetails = null;

    protected ?string $issuerState = null;

    protected bool $issuerStateIsValid = true;

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

    /** @var array<array{error: string, description: string, httpCode: int}> Refusals the endpoint answered with. */
    protected array $errorResponses = [];

    /** @var array<array<array-key,mixed>> Successful responses the endpoint answered with. */
    protected array $jsonResponses = [];

    /** @var \SimpleSAML\OpenID\SdJwt\DisclosureBag[] One per credential built in an SD-JWT format. */
    protected array $disclosureBags = [];


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
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
        $this->openId4VciProofValidatorMock = $this->createMock(OpenId4VciProofValidator::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);
        $this->credentialStatusIssuerMock = $this->createMock(CredentialStatusIssuer::class);
        $this->helpers = new Helpers();
        $this->signedPayloads = [];
        $this->signedWith = [];
        $this->errorResponses = [];
        $this->jsonResponses = [];
        $this->disclosureBags = [];

        // A request which should be issued: a pre-authorized-code access token, found and unrevoked,
        // naming a user and a credential configuration this issuer supports. Each test spoils exactly
        // one of these, so a check which stopped refusing falls through to the success path and fails
        // for the absent refusal rather than passing.
        $this->flowType = FlowTypeEnum::VciPreAuthorizedCode;
        $this->accessTokenIsFound = true;
        $this->accessTokenIsRevoked = false;
        $this->accessTokenUserIdentifier = 'user123';
        $this->authorizationDetails = null;
        $this->issuerState = null;
        $this->issuerStateIsValid = true;
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
        ];
        $this->requestData = [ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID];
        $this->validatedProofs = [];
        $this->proofValidationException = null;
        $this->userClaims = [];
        $this->validClaimPaths = [];
        $this->attributeToClaimPathMap = [];

        // VCI must be enabled in constructor
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getVciIssuerIdentifier')
            ->willReturn(new VciIssuerIdentifier(VciIssuerIdentifierModeEnum::DidJwk));
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturnCallback(fn(): ?array => $this->credentialConfiguration);
        $this->moduleConfigMock->method('getVciValidCredentialClaimPathsFor')
            ->willReturnCallback(fn(): array => $this->validClaimPaths);
        $this->moduleConfigMock->method('getVciUserAttributeToCredentialClaimPathMapFor')
            ->willReturnCallback(fn(): array => $this->attributeToClaimPathMap);
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound;
        $this->moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturnCallback(fn(): VciCredentialBindingPolicyEnum => $this->bindingPolicy);

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
        $authorizationMock->method('getAttribute')->with('oauth_access_token_id')->willReturn('token_id');
        $this->resourceServerMock->method('validateAuthenticatedRequest')->willReturn($authorizationMock);

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
        $this->accessTokenMock->method('isRevoked')
            ->willReturnCallback(fn(): bool => $this->accessTokenIsRevoked);
        $this->accessTokenRepositoryMock->method('findById')->with('token_id')->willReturnCallback(
            fn(): ?AccessTokenEntity => $this->accessTokenIsFound ? $this->accessTokenMock : null,
        );

        $this->issuerStateRepositoryMock->method('findValid')->willReturnCallback(
            fn(): ?IssuerStateEntity => $this->issuerStateIsValid
                ? $this->createMock(IssuerStateEntity::class)
                : null,
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
        $this->routesMock->method('newJsonResponse')->willReturnCallback(
            function (?array $data = null): JsonResponse {
                $this->jsonResponses[] = $data ?? [];

                return $this->createMock(JsonResponse::class);
            },
        );

        $this->routesMock->method('newJsonErrorResponse')->willReturnCallback(
            function (string $error, string $description, int $httpCode = 500): JsonResponse {
                $this->errorResponses[] = [
                    'error' => $error,
                    'description' => $description,
                    'httpCode' => $httpCode,
                ];

                return $this->createMock(JsonResponse::class);
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
        $keyPairMock->method('getPrivateKey')->willReturn($this->vciPrivateKeyMock);
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
                $this->signedWith[] = ['key' => $key, 'algorithm' => $algorithm];

                return $jwtVcJsonMock;
            },
        );
        $this->verifiableCredentialsMock->method('jwtVcJsonFactory')->willReturn($jwtVcJsonFactoryMock);

        $sdJwtVcMock = $this->createMock(SdJwtVc::class);
        $sdJwtVcMock->method('getToken')->willReturn('sd_jwt_token');
        $sdJwtVcFactoryMock = $this->createMock(SdJwtVcFactory::class);
        $sdJwtVcFactoryMock->method('fromData')->willReturnCallback(
            function (mixed $key, mixed $algorithm, array $payload) use ($sdJwtVcMock): SdJwtVc {
                $this->signedPayloads[] = $payload;
                $this->signedWith[] = ['key' => $key, 'algorithm' => $algorithm];

                return $sdJwtVcMock;
            },
        );
        $this->verifiableCredentialsMock->method('sdJwtVcFactory')->willReturn($sdJwtVcFactoryMock);

        $vcSdJwtMock = $this->createMock(VcSdJwt::class);
        $vcSdJwtMock->method('getToken')->willReturn('vc_sd_jwt_token');
        $vcSdJwtFactoryMock = $this->createMock(VcSdJwtFactory::class);
        $vcSdJwtFactoryMock->method('fromData')->willReturnCallback(
            function (mixed $key, mixed $algorithm, array $payload) use ($vcSdJwtMock): VcSdJwt {
                $this->signedPayloads[] = $payload;
                $this->signedWith[] = ['key' => $key, 'algorithm' => $algorithm];

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
    ): void {
        $this->credentialConfiguration = [ClaimsEnum::Format->value => $format];

        $this->requestData = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => $proofJwts],
        ];

        $validatedProofs = [];
        foreach ($proofJwts as $ignored) {
            $validatedProofs[] = $this->validatedProof($inlineKey);
        }
        $this->validatedProofs = $validatedProofs;

        $this->dispatch();
    }


    /**
     * A key proof which passed every check, resolved to the holder it names.
     *
     * @param ?array<array-key,mixed> $inlineKey The key a proof carried inline, for a proof which named
     * no verification method.
     */
    protected function validatedProof(?array $inlineKey = null): ValidatedOpenId4VciProof
    {
        return new ValidatedOpenId4VciProof(
            $this->createMock(OpenId4VciProof::class),
            self::HOLDER_DID,
            $inlineKey === null ? self::HOLDER_DID . '#0' : null,
            $inlineKey,
        );
    }


    /**
     * @param ?array<string,mixed> $requestData Defaults to the scenario's own request parameters.
     */
    protected function dispatch(?array $requestData = null): void
    {
        $requestData ??= $this->requestData;

        $request = new Request([], [], [], [], [], [], json_encode($requestData));
        $request->setMethod('POST');

        $this->sut()->credential($request);
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
            $this->verifiableCredentialsMock,
            $this->loggerServiceMock,
            $this->requestParamsResolverMock,
            $this->userRepositoryMock,
            $this->vciIssuerIdentityResolverMock,
            $this->issuerStateRepositoryMock,
            $this->vciIssuerIdentityRepositoryMock,
            $this->openId4VciProofValidatorMock,
            $this->vciContextResolverMock,
            $this->credentialStatusIssuerMock,
            $this->helpers,
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
     * A configuration which advertises no proof type issues one credential, to a subject identifier of
     * this issuer's own making, and asks the validator for nothing more than that.
     */
    public function testAProoflessConfigurationIssuesOneUnboundCredential(): void
    {
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::Proofless;

        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
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


    public function testTheStatusListEntryIsAllocatedWithTheCredentialLifetime(): void
    {
        $this->moduleConfigMock->method('getVciCredentialTtlFor')->willReturn(new DateInterval('P30D'));

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

        $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
        $this->assertSame([], $this->signedPayloads);
    }


    public function testAnswersWithInvalidTokenWhenTheAccessTokenIsRevoked(): void
    {
        $this->accessTokenIsRevoked = true;

        $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
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

        $this->dispatch();

        $this->assertRefusedWith('invalid_token', 401);
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
     * The authorization-code flow records an issuer state when the offer is made, and the credential
     * request is only redeemable against it. A token which carries none is one this endpoint can not
     * tie back to an offer.
     */
    public function testRefusesAnAuthorizationCodeFlowCarryingNoIssuerState(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = null;

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 401);
        $this->assertSame([], $this->signedPayloads);
    }


    public function testRefusesAnIssuerStateWhichIsNoLongerValid(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = 'issuer-state-1';
        $this->issuerStateIsValid = false;

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 401);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * One offer, one credential request: the state is spent as soon as it has been redeemed, so the
     * same authorization can not be presented again for a second credential.
     */
    public function testSpendsTheIssuerStateOnceCredentialsAreIssued(): void
    {
        $this->flowType = FlowTypeEnum::VciAuthorizationCode;
        $this->issuerState = 'issuer-state-1';

        $this->issuerStateRepositoryMock->expects($this->once())->method('revoke')->with('issuer-state-1');

        $this->issue();

        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * A pre-authorized-code flow has no issuer state to spend, and nothing is revoked on its behalf.
     */
    public function testSpendsNoIssuerStateForAPreAuthorizedCodeFlow(): void
    {
        $this->issuerStateRepositoryMock->expects($this->never())->method('revoke');

        $this->issue();

        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * The two parameters name a credential in two different ways, and a request uses one of them.
     * Picking one would mean guessing which credential was meant.
     */
    public function testRefusesACredentialConfigurationIdSentTogetherWithACredentialIdentifier(): void
    {
        $this->requestData = [
            ClaimsEnum::CredentialConfigurationId->value => self::CONFIGURATION_ID,
            ClaimsEnum::CredentialIdentifier->value => self::CONFIGURATION_ID,
        ];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
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

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
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
     * With neither identifier and no format either, there is nothing left to resolve a configuration
     * from.
     */
    public function testRefusesWhenNeitherAnIdentifierNorAFormatWasSent(): void
    {
        $this->requestData = [];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A format outside the three this issuer can produce is refused as a format, rather than left to
     * fail later as a credential no branch knows how to build.
     */
    public function testRefusesAFormatItCanNotIssue(): void
    {
        $this->requestData = [ClaimsEnum::Format->value => 'mso_mdoc'];

        $this->dispatch();

        $this->assertRefusedWith('unsupported_credential_type', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * A wallet which names no configuration can still be served when what it did send identifies one:
     * the credential definition's types, for the W3C format.
     */
    public function testResolvesTheConfigurationFromTheCredentialDefinitionType(): void
    {
        $this->requestData = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
            ClaimsEnum::CredentialDefinition->value => [
                ClaimsEnum::Type->value => ['VerifiableCredential', 'UniversityDegree'],
            ],
        ];
        $this->validatedProofs = [$this->validatedProof()];

        $this->moduleConfigMock->expects($this->once())
            ->method('getVciCredentialConfigurationIdForCredentialDefinitionType')
            ->with(['VerifiableCredential', 'UniversityDegree'])
            ->willReturn(self::CONFIGURATION_ID);

        $this->dispatch();

        $this->assertSame([], $this->errorResponses);
        $this->assertCount(1, $this->signedPayloads);
    }


    /**
     * And the `vct`, for the SD-JWT formats, where the credential type is the configuration identifier.
     */
    public function testResolvesTheConfigurationFromTheVct(): void
    {
        $this->credentialConfiguration = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
        ];
        $this->requestData = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value,
            ClaimsEnum::Vct->value => self::CONFIGURATION_ID,
        ];
        $this->validatedProofs = [$this->validatedProof()];

        $this->dispatch();

        $this->assertSame([], $this->errorResponses);
        $this->assertSame(
            self::CONFIGURATION_ID,
            $this->signedPayloads[0][ClaimsEnum::Vct->value] ?? null,
        );
    }


    /**
     * A supported format on its own is not enough: something has to say which configuration is being
     * asked for.
     */
    public function testRefusesWhenFallbackResolutionFindsNothing(): void
    {
        $this->requestData = [
            ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value,
        ];

        $this->dispatch();

        $this->assertRefusedWith('invalid_credential_request', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    public function testRefusesAnUnknownCredentialConfiguration(): void
    {
        $this->credentialConfiguration = null;

        $this->dispatch();

        $this->assertRefusedWith('unsupported_credential_type', 400);
        $this->assertSame([], $this->signedPayloads);
    }


    /**
     * Format is what decides how a credential is built, so a configuration without one is this
     * issuer's own misconfiguration rather than a bad request, and is answered as such.
     */
    public function testFailsWhenTheResolvedConfigurationStatesNoFormat(): void
    {
        $this->credentialConfiguration = [];

        $this->expectException(OidcServerException::class);

        $this->dispatch();
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
     * The credential is about a user, so an access token which names none is not one a credential can
     * be issued against.
     */
    public function testFailsWhenTheAccessTokenNamesNoUser(): void
    {
        $this->accessTokenUserIdentifier = null;

        $this->expectException(OidcServerException::class);

        $this->dispatch();
    }


    public function testFailsWhenTheUserIsNotFound(): void
    {
        $this->userEntity = null;

        $this->expectException(OidcServerException::class);

        $this->dispatch();
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
