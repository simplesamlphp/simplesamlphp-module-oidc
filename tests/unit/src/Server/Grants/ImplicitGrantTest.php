<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestTypes\AuthorizationRequest;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core\IdToken;

#[CoversClass(ImplicitGrant::class)]
class ImplicitGrantTest extends TestCase
{
    protected MockObject $idTokenBuilderMock;
    protected \DateInterval $accessTokenTtl1h;
    protected MockObject $accessTokenRepositoryMock;
    protected MockObject $requestRulesManagerMock;
    protected MockObject $requestParamsResolverMock;
    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $scopeRepositoryMock;
    protected MockObject $serverRequestMock;
    protected MockObject $authorizationRequestMock;
    protected MockObject $userEntityMock;
    protected MockObject $scopeEntityMock;
    protected MockObject $clientEntityMock;
    protected MockObject $resultBagMock;
    protected MockObject $loggerServiceMock;

    protected function setUp(): void
    {
        $this->idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $this->accessTokenTtl1h = new \DateInterval('PT1H');
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->authorizationRequestMock = $this->createMock(AuthorizationRequest::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);
        $this->scopeEntityMock = $this->createMock(ScopeEntityInterface::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->resultBagMock = $this->createMock(ResultBagInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }

    protected function sut(
        ?IdTokenBuilder $idTokenBuilder = null,
        ?\DateInterval $accessTokenTtl = null,
        ?AccessTokenRepositoryInterface $accessTokenRepository = null,
        ?RequestRulesManager $requestRulesManager = null,
        ?RequestParamsResolver $requestParamsResolver = null,
        ?AccessTokenEntityFactory $accessTokenEntityFactory = null,
        ?ScopeRepositoryInterface $scopeRepository = null,
        ?LoggerService $loggerService = null,
    ): ImplicitGrant {
        $idTokenBuilder ??= $this->idTokenBuilderMock;
        $accessTokenTtl ??= $this->accessTokenTtl1h;
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $requestRulesManager ??= $this->requestRulesManagerMock;
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $accessTokenEntityFactory ??= $this->accessTokenEntityFactoryMock;
        $scopeRepository ??= $this->scopeRepositoryMock;
        $loggerService ??= $this->loggerServiceMock;


        $implicitGrant = new ImplicitGrant(
            $idTokenBuilder,
            $accessTokenTtl,
            $accessTokenRepository,
            $requestRulesManager,
            $requestParamsResolver,
            $accessTokenEntityFactory,
            $loggerService,
        );

        $implicitGrant->setScopeRepository($scopeRepository);

        return $implicitGrant;
    }

    public function testCanConstruct(): void
    {
        $this->assertInstanceOf(ImplicitGrant::class, $this->sut());
    }

    public function testCanRespondToAuthorizationRequestForIdTokenTokenResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'id_token token']);

        $this->assertTrue($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }

    public function testCanRespondToAuthorizationRequestForIdTokenResponseType(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['client_id' => 'clientId', 'response_type' => 'id_token']);

        $this->assertTrue($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }

    public function testCanRespondToAuthorizationRequestReturnsFalseIfNoClientId(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['response_type' => 'id_token']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }

    public function testCanRespondToAuthorizationRequestReturnsFalseForHybridFlow(): void
    {
        $this->requestParamsResolverMock->expects($this->once())
            ->method('getAllBasedOnAllowedMethods')
            ->willReturn(['response_type' => 'code id_token']);

        $this->assertFalse($this->sut()->canRespondToAuthorizationRequest($this->serverRequestMock));
    }

    public function testCompleteAuthorizationRequestThrowsForNonOidcRequests(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Unexpected');

        $this->sut()->completeAuthorizationRequest($this->createMock(
            \League\OAuth2\Server\RequestTypes\AuthorizationRequest::class,
        ));
    }

    public function testCanCompleteAuthorizationRequest(): void
    {
        $this->authorizationRequestMock->expects($this->once())->method('getUser')
            ->willReturn($this->userEntityMock);
        $this->authorizationRequestMock->expects($this->once())->method('getRedirectUri')
            ->willReturn('redirectUri');
        $this->authorizationRequestMock->expects($this->once())->method('isAuthorizationApproved')
            ->willReturn(true);
        $this->authorizationRequestMock->expects($this->once())->method('getScopes')
            ->willReturn([$this->scopeEntityMock]);
        $this->authorizationRequestMock->method('getClient')
            ->willReturn($this->clientEntityMock);
        $this->scopeRepositoryMock->expects($this->once())->method('finalizeScopes')
            ->willReturn([$this->scopeEntityMock]);

        $this->assertInstanceOf(
            RedirectResponse::class,
            $this->sut()->completeAuthorizationRequest($this->authorizationRequestMock),
        );
    }

    /**
     * The grant forwards the "add claims to ID Token" decision (made by AddClaimsToIdTokenRule and carried on the
     * authorization request) to the ID Token builder. When it is true, the user's claims are released in the ID
     * Token.
     */
    public function testReleasesUserClaimsInIdTokenWhenRequested(): void
    {
        $this->authorizationRequestMock->method('getUser')->willReturn($this->userEntityMock);
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn('redirectUri');
        $this->authorizationRequestMock->method('isAuthorizationApproved')->willReturn(true);
        $this->authorizationRequestMock->method('getScopes')->willReturn([$this->scopeEntityMock]);
        $this->authorizationRequestMock->method('getClient')->willReturn($this->clientEntityMock);
        $this->authorizationRequestMock->method('getAddClaimsToIdToken')->willReturn(true);
        $this->scopeRepositoryMock->method('finalizeScopes')->willReturn([$this->scopeEntityMock]);

        $idTokenMock = $this->createMock(IdToken::class);
        $idTokenMock->method('getToken')->willReturn('token');
        $this->idTokenBuilderMock->expects($this->once())
            ->method('buildFor')
            ->with(
                $this->anything(),
                $this->anything(),
                true, // $addClaimsFromScopes
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn($idTokenMock);

        $this->sut()->completeAuthorizationRequest($this->authorizationRequestMock);
    }

    /**
     * When the decision is false, the user's claims are not released in the ID Token (they remain available at
     * the UserInfo endpoint via the issued access token).
     */
    public function testDoesNotReleaseUserClaimsInIdTokenWhenNotRequested(): void
    {
        $this->authorizationRequestMock->method('getUser')->willReturn($this->userEntityMock);
        $this->authorizationRequestMock->method('getRedirectUri')->willReturn('redirectUri');
        $this->authorizationRequestMock->method('isAuthorizationApproved')->willReturn(true);
        $this->authorizationRequestMock->method('getScopes')->willReturn([$this->scopeEntityMock]);
        $this->authorizationRequestMock->method('getClient')->willReturn($this->clientEntityMock);
        $this->authorizationRequestMock->method('getAddClaimsToIdToken')->willReturn(false);
        $this->scopeRepositoryMock->method('finalizeScopes')->willReturn([$this->scopeEntityMock]);

        $idTokenMock = $this->createMock(IdToken::class);
        $idTokenMock->method('getToken')->willReturn('token');
        $this->idTokenBuilderMock->expects($this->once())
            ->method('buildFor')
            ->with(
                $this->anything(),
                $this->anything(),
                false, // $addClaimsFromScopes
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
                $this->anything(),
            )
            ->willReturn($idTokenMock);

        $this->sut()->completeAuthorizationRequest($this->authorizationRequestMock);
    }

    public function testCanValidateAuthorizationRequestWithRequestRules(): void
    {
        $this->markTestIncomplete('RequestRulesManager needs to be refactored so it can be strongly typed.');
    }
}
