<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\Interfaces\AccessTokenRepositoryInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
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
        bool $disallowImplicitForConfidentialClients = false,
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
            $disallowImplicitForConfidentialClients,
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

    protected function resultBagFor(bool $isConfidential): ResultBag
    {
        $this->clientEntityMock->method('isConfidential')->willReturn($isConfidential);

        $resultBag = new ResultBag();
        $resultBag->add(new Result(RedirectUriRule::class, 'https://example.com/callback'));
        $resultBag->add(new Result(StateRule::class, 'test-state'));
        $resultBag->add(new Result(ClientIdRule::class, $this->clientEntityMock));

        return $resultBag;
    }

    public function testValidateAuthorizationRequestRefusesConfidentialClientWhenDisallowed(): void
    {
        $this->requestRulesManagerMock->expects($this->never())->method('check');

        $responseMock = $this->createMock(ResponseInterface::class);
        $responseMock->expects($this->once())->method('withStatus')->with(302)->willReturnSelf();
        $responseMock->expects($this->once())->method('withHeader')
            ->with(
                'Location',
                'https://example.com/callback#' . http_build_query([
                    'error' => 'unauthorized_client',
                    'error_description' => 'The client is not authorized to request a token using this method. ' .
                        '(Confidential clients are not allowed to use the implicit grant.)',
                    'state' => 'test-state',
                ]),
            )
            ->willReturnSelf();

        try {
            $this->sut(disallowImplicitForConfidentialClients: true)
                ->validateAuthorizationRequestWithRequestRules($this->serverRequestMock, $this->resultBagFor(true));
            $this->fail('The request should have been refused.');
        } catch (OidcServerException $exception) {
            $this->assertSame('unauthorized_client', $exception->getErrorType());
            $exception->generateHttpResponse($responseMock);
        }
    }

    public function testValidateAuthorizationRequestContinuesForPublicClientWhenDisallowed(): void
    {
        // The rule check is where the request goes next; failing there stops the test before the rest of the flow.
        $this->requestRulesManagerMock->expects($this->once())->method('check')
            ->willThrowException(new RuntimeException('rules executed'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rules executed');

        $this->sut(disallowImplicitForConfidentialClients: true)
            ->validateAuthorizationRequestWithRequestRules($this->serverRequestMock, $this->resultBagFor(false));
    }

    public function testValidateAuthorizationRequestContinuesForConfidentialClientByDefault(): void
    {
        $this->requestRulesManagerMock->expects($this->once())->method('check')
            ->willThrowException(new RuntimeException('rules executed'));

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('rules executed');

        $this->sut()->validateAuthorizationRequestWithRequestRules($this->serverRequestMock, $this->resultBagFor(true));
    }
}
