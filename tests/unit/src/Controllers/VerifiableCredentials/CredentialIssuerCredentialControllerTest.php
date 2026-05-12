<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\VerifiableCredentials;

use Jose\Component\Core\JWK;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Bridges\PsrHttpBridge;
use SimpleSAML\Module\oidc\Codebooks\FlowTypeEnum;
use SimpleSAML\Module\oidc\Controllers\VerifiableCredentials\CredentialIssuerCredentialController;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\IssuerStateRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResourceServer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\NonceService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\VciContextResolver;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Did;
use SimpleSAML\OpenID\Did\DidJwkResolver;
use SimpleSAML\OpenID\Helpers as VcHelpers;
use SimpleSAML\OpenID\Helpers\Arr as VcArr;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\ValueAbstracts\KeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPair;
use SimpleSAML\OpenID\ValueAbstracts\SignatureKeyPairBag;
use SimpleSAML\OpenID\VerifiableCredentials as VerifiableCredentialsService;
use SimpleSAML\OpenID\VerifiableCredentials\Factories\OpenId4VciProofFactory;
use SimpleSAML\OpenID\VerifiableCredentials\OpenId4VciProof;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel\Factories\JwtVcJsonFactory;
use SimpleSAML\OpenID\VerifiableCredentials\VcDataModel\JwtVcJson;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class CredentialIssuerCredentialControllerTest extends TestCase
{
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
    protected MockObject $nonceServiceMock;
    protected MockObject $vciContextResolverMock;

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
        $this->nonceServiceMock = $this->createMock(NonceService::class);
        $this->vciContextResolverMock = $this->createMock(VciContextResolver::class);

        // VCI must be enabled in constructor
        $this->moduleConfigMock->method('getVciEnabled')->willReturn(true);
    }

    public function testCredentialWithMultipleProofs(): void
    {
        $requestData = [
            'credential_configuration_id' => 'test_id',
            'proofs' => [
                'jwt' => ['jwt1', 'jwt2'],
            ],
        ];
        $request = new Request([], [], [], [], [], [], json_encode($requestData));
        $request->setMethod('POST');

        // Mock PsrHttpBridge
        $psrRequestMock = $this->createMock(ServerRequestInterface::class);
        $psrFactoryMock = $this->createMock(PsrHttpFactory::class);
        $psrFactoryMock->method('createRequest')->willReturn($psrRequestMock);
        $this->psrHttpBridgeMock->method('getPsrHttpFactory')->willReturn($psrFactoryMock);

        // Mock RequestParamsResolver
        $this->requestParamsResolverMock->method('getAllFromRequestBasedOnAllowedMethods')->willReturn($requestData);

        // Mock ResourceServer validation
        $authorizationMock = $this->createMock(ServerRequestInterface::class);
        $authorizationMock->method('getAttribute')->with('oauth_access_token_id')->willReturn('token_id');
        $this->resourceServerMock->method('validateAuthenticatedRequest')->willReturn($authorizationMock);

        $accessToken = $this->createMock(AccessTokenEntity::class);
        $this->accessTokenRepositoryMock->method('findById')->with('token_id')->willReturn($accessToken);

        $accessToken->method('getFlowTypeEnum')->willReturn(FlowTypeEnum::VciPreAuthorizedCode);
        $accessToken->method('getUserIdentifier')->willReturn('user123');
        $accessToken->method('getAuthorizationDetails')->willReturn(null);
        $accessToken->method('getIssuerState')->willReturn(null);
        $accessToken->method('isRevoked')->willReturn(false);

        $this->moduleConfigMock->method('getVciCredentialConfiguration')->willReturn(['format' => 'jwt_vc_json']);
        $this->moduleConfigMock->method('getIssuer')->willReturn('https://issuer.com');
        $this->moduleConfigMock->method('getVciValidCredentialClaimPathsFor')->willReturn([]);
        $this->moduleConfigMock->method('getVciUserAttributeToCredentialClaimPathMapFor')->willReturn([]);

        $userEntity = $this->createMock(UserEntity::class);
        $userEntity->method('getClaims')->willReturn([]);
        $this->userRepositoryMock->method('getUserEntityByIdentifier')->willReturn($userEntity);

        $proofFactoryMock = $this->createMock(OpenId4VciProofFactory::class);
        $this->verifiableCredentialsMock->method('openId4VciProofFactory')->willReturn($proofFactoryMock);

        $proofMock1 = $this->createMock(OpenId4VciProof::class);
        $proofMock1->method('getAudience')->willReturn(['https://issuer.com']);
        $proofMock1->method('getJsonWebKey')->willReturn(['kty' => 'EC']);
        $proofMock1->method('getNonce')->willReturn(null);

        $proofMock2 = $this->createMock(OpenId4VciProof::class);
        $proofMock2->method('getAudience')->willReturn(['https://issuer.com']);
        $proofMock2->method('getJsonWebKey')->willReturn(['kty' => 'EC']);
        $proofMock2->method('getNonce')->willReturn(null);

        $proofFactoryMock->expects($this->exactly(2))
            ->method('fromToken')
            ->willReturnOnConsecutiveCalls($proofMock1, $proofMock2);

        $didJwkResolverMock = $this->createMock(DidJwkResolver::class);
        $this->didMock->method('didJwkResolver')->willReturn($didJwkResolverMock);
        $didJwkResolverMock->method('generateDidJwkFromJwk')->willReturn('did:jwk:test');

        $vcHelpersMock = $this->createMock(VcHelpers::class);
        $this->verifiableCredentialsMock->method('helpers')->willReturn($vcHelpersMock);
        $vcArrMock = $this->createMock(VcArr::class);
        $vcHelpersMock->method('arr')->willReturn($vcArrMock);

        $jwtVcJsonFactoryMock = $this->createMock(JwtVcJsonFactory::class);
        $this->verifiableCredentialsMock->method('jwtVcJsonFactory')->willReturn($jwtVcJsonFactoryMock);

        $vcMock = $this->createMock(JwtVcJson::class);
        $vcMock->method('getToken')->willReturn('vc_token');
        $jwtVcJsonFactoryMock->method('fromData')->willReturn($vcMock);

        $keyPairMock = $this->createMock(KeyPair::class);
        $keyPairMock->method('getPrivateKey')->willReturn($this->createMock(JwkDecorator::class));
        $publicKeyMock = $this->createMock(JwkDecorator::class);
        $jwkMock = $this->createMock(JWK::class);
        $jwkMock->method('all')->willReturn(['kty' => 'EC']);
        $publicKeyMock->method('jwk')->willReturn($jwkMock);
        $keyPairMock->method('getPublicKey')->willReturn($publicKeyMock);

        $signatureKeyPairMock = $this->createMock(SignatureKeyPair::class);
        $signatureKeyPairMock->method('getKeyPair')->willReturn($keyPairMock);
        $signatureKeyPairMock->method('getSignatureAlgorithm')->willReturn(SignatureAlgorithmEnum::ES256);

        $signatureKeyPairBagMock = $this->createMock(SignatureKeyPairBag::class);
        $signatureKeyPairBagMock->method('getFirstOrFail')->willReturn($signatureKeyPairMock);
        $this->moduleConfigMock->method('getVciSignatureKeyPairBag')->willReturn($signatureKeyPairBagMock);

        $this->routesMock->expects($this->once())
            ->method('newJsonResponse')
            ->with($this->callback(function ($data) {
                return isset($data['credentials']) && count($data['credentials']) === 2;
            }))
            ->willReturn($this->createMock(JsonResponse::class));

        $sut = new CredentialIssuerCredentialController(
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
            $this->nonceServiceMock,
            $this->vciContextResolverMock,
        );

        $sut->credential($request);
    }
}
