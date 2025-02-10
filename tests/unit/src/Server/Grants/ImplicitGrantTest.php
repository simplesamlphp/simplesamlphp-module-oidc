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
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

#[CoversClass(ImplicitGrant::class)]
class ImplicitGrantTest extends TestCase
{
    protected MockObject $idTokenBuilderMock;
    protected \DateInterval $accessTokenTtl1h;
    protected MockObject $accessTokenRepositoryMock;
    protected MockObject $requestRulesManagerMock;
    protected MockObject $requestParamsResolverMock;
    protected string $queryDelimiter;
    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $scopeRepositoryMock;
    protected MockObject $serverRequestMock;
    protected MockObject $authorizationRequestMock;
    protected MockObject $userEntityMock;
    protected MockObject $scopeEntityMock;
    protected MockObject $clientEntityMock;
    protected MockObject $resultBagMock;

    protected function setUp(): void
    {
        $this->idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $this->accessTokenTtl1h = new \DateInterval('PT1H');
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->queryDelimiter = '#';
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepositoryInterface::class);

        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
        $this->authorizationRequestMock = $this->createMock(AuthorizationRequest::class);
        $this->userEntityMock = $this->createMock(UserEntity::class);
        $this->scopeEntityMock = $this->createMock(ScopeEntityInterface::class);
        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->resultBagMock = $this->createMock(ResultBagInterface::class);
    }

    protected function sut(
        ?IdTokenBuilder $idTokenBuilder = null,
        ?\DateInterval $accessTokenTtl = null,
        ?AccessTokenRepositoryInterface $accessTokenRepository = null,
        ?RequestRulesManager $requestRulesManager = null,
        ?RequestParamsResolver $requestParamsResolver = null,
        ?string $queryDelimiter = null,
        ?AccessTokenEntityFactory $accessTokenEntityFactory = null,
        ?ScopeRepositoryInterface $scopeRepository = null,
    ): ImplicitGrant {
        $idTokenBuilder ??= $this->idTokenBuilderMock;
        $accessTokenTtl ??= $this->accessTokenTtl1h;
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $requestRulesManager ??= $this->requestRulesManagerMock;
        $requestParamsResolver ??= $this->requestParamsResolverMock;
        $queryDelimiter ??= $this->queryDelimiter;
        $accessTokenEntityFactory ??= $this->accessTokenEntityFactoryMock;
        $scopeRepository ??= $this->scopeRepositoryMock;


        $implicitGrant = new ImplicitGrant(
            $idTokenBuilder,
            $accessTokenTtl,
            $accessTokenRepository,
            $requestRulesManager,
            $requestParamsResolver,
            $queryDelimiter,
            $accessTokenEntityFactory,
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

    public function testCanValidateAuthorizationRequestWithRequestRules(): void
    {
        $this->markTestIncomplete('RequestRulesManager needs to be refactored so it can be strongly typed.');
    }
}
