<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Codebooks\VciCredentialBindingPolicyEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerCredentialController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Exceptions\CredentialRequestException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusIssuer;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\Module\oidc\VerifiableCredentials\OpenId4VciProofValidator;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\ValidatedOpenId4VciProof;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\CredentialFormatIdentifiersEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Helpers as VcHelpers;
use SimpleSAML\OpenID\Helpers\Arr as VcArr;
use SimpleSAML\OpenID\Jwk\Factories\JwkDecoratorFactory;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
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

#[AllowMockObjectsWithoutExpectations]
class CredentialIssuerCredentialControllerTest extends TestCase
{
    protected const string CONFIGURATION_ID = 'test_id';

    protected const string ISSUER = 'https://issuer.com';

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

    protected MockObject $didMock;

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
        $this->didMock = $this->createMock(Did::class);
        $this->issuerStateRepositoryMock = $this->createMock(IssuerStateRepository::class);
        $this->openId4VciProofValidatorMock = $this->createMock(OpenId4VciProofValidator::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);
        $this->credentialStatusIssuerMock = $this->createMock(CredentialStatusIssuer::class);
        $this->helpers = new Helpers();
        $this->signedPayloads = [];
        $this->signedWith = [];

        // VCI must be enabled in constructor
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getVciValidCredentialClaimPathsFor')->willReturn([]);
        $this->moduleConfigMock->method('getVciUserAttributeToCredentialClaimPathMapFor')->willReturn([]);
        $this->bindingPolicy = VciCredentialBindingPolicyEnum::ProofBound;
        $this->moduleConfigMock->method('getVciCredentialBindingPolicyFor')
            ->willReturnCallback(fn(): VciCredentialBindingPolicyEnum => $this->bindingPolicy);

        $this->prepareRequestPipeline();
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

        $accessToken = $this->createMock(AccessTokenEntity::class);
        $accessToken->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $accessToken->method('getUserIdentifier')->willReturn('user123');
        $accessToken->method('getAuthorizationDetails')->willReturn(null);
        $accessToken->method('getIssuerState')->willReturn(null);
        $accessToken->method('isRevoked')->willReturn(false);
        $this->accessTokenRepositoryMock->method('findById')->with('token_id')->willReturn($accessToken);
    }


    protected function prepareUser(): void
    {
        $userEntity = $this->createMock(UserEntity::class);
        $userEntity->method('getClaims')->willReturn([]);
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->willReturn($userEntity);
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

        $didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didMock->method('didJwkResolver')->willReturn($didJwkResolverMock);
        $didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn('did:jwk:test');

        $vcHelpersMock = $this->createMock(VcHelpers::class);
        $this->verifiableCredentialsMock->method('helpers')->willReturn($vcHelpersMock);
        $vcHelpersMock->method('arr')->willReturn($this->createMock(VcArr::class));
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
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturn([ClaimsEnum::Format->value => $format]);

        $requestData = [
            'credential_configuration_id' => self::CONFIGURATION_ID,
            'proofs' => ['jwt' => $proofJwts],
        ];
        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')
            ->willReturn($requestData);

        $validatedProofs = [];
        foreach ($proofJwts as $ignored) {
            $validatedProofs[] = new ValidatedOpenId4VciProof(
                $this->createMock(OpenId4VciProof::class),
                self::HOLDER_DID,
                $inlineKey === null ? self::HOLDER_DID . '#0' : null,
                $inlineKey,
            );
        }
        $this->openId4VciProofValidatorMock->method('validateRequest')->willReturn($validatedProofs);

        $this->dispatch($requestData);
    }


    /**
     * @param array<string,mixed> $requestData
     */
    protected function dispatch(array $requestData): void
    {
        $request = new Request([], [], [], [], [], [], json_encode($requestData));
        $request->setMethod('POST');

        $this->sut()->credential($request);
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
            $this->didMock,
            $this->issuerStateRepositoryMock,
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

        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturn([ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::DcSdJwt->value]);
        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')
            ->willReturn(['credential_configuration_id' => self::CONFIGURATION_ID]);
        $this->openId4VciProofValidatorMock->method('validateRequest')->willReturn([null]);

        $this->dispatch(['credential_configuration_id' => self::CONFIGURATION_ID]);

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
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturn([ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value]);
        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')
            ->willReturn(['credential_configuration_id' => self::CONFIGURATION_ID]);
        $this->openId4VciProofValidatorMock->method('validateRequest')->willThrowException(
            new CredentialRequestException('invalid_nonce', 'c_nonce is invalid or expired.'),
        );

        $this->routesMock->expects($this->never())->method('newJsonResponse');
        $this->routesMock->expects($this->once())
            ->method('newJsonErrorResponse')
            ->with('invalid_nonce', $this->anything(), 400)
            ->willReturn($this->createMock(JsonResponse::class));

        $this->dispatch(['credential_configuration_id' => self::CONFIGURATION_ID]);

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
        $this->moduleConfigMock->method('getVciCredentialConfiguration')
            ->willReturn([ClaimsEnum::Format->value => CredentialFormatIdentifiersEnum::JwtVcJson->value]);
        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')
            ->willReturn(['credential_configuration_id' => self::CONFIGURATION_ID]);
        $this->openId4VciProofValidatorMock->method('validateRequest')->willThrowException(
            new CredentialRequestException('invalid_proof', 'Key proof signature could not be verified.'),
        );

        $this->credentialStatusIssuerMock->expects($this->never())->method('issueFor');
        $this->routesMock->method('newJsonErrorResponse')->willReturn($this->createMock(JsonResponse::class));

        $this->dispatch(['credential_configuration_id' => self::CONFIGURATION_ID]);

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
}
