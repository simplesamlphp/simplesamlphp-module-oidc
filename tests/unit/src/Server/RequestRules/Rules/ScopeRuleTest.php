<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\Builder\InvocationStubber;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Str;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule
 */
#[AllowMockObjectsWithoutExpectations]
class ScopeRuleTest extends TestCase
{
    protected Stub $scopeRepositoryStub;

    protected Stub $resultBagStub;

    protected array $data = [
        'default_scope' => '',
        'scope_delimiter_string' => ' ',
    ];

    protected string $scopes = 'openid profile';

    protected array $scopeEntities = [];

    protected Result $redirectUriResult;

    protected Result $stateResult;

    protected Stub $requestStub;

    protected Stub $loggerServiceStub;

    protected Stub $requestParamsResolverStub;

    protected Stub $helpersStub;

    protected Stub $strHelperMock;

    protected Stub $responseModeStub;

    protected Stub $moduleConfigStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->scopeRepositoryStub = $this->createStub(ScopeRepositoryInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(ClientRedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->scopeEntities = [
            'openid' => new ScopeEntity('openid'),
            'profile' => new ScopeEntity('profile'),
        ];
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpersStub = $this->createStub(Helpers::class);
        $this->strHelperMock = $this->createMock(Str::class);
        $this->helpersStub->method('str')->willReturn($this->strHelperMock);
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
        // A credential configuration whose metadata states no scope.
        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getVciCredentialConfigurationIdsWithoutScope')
            ->willReturn(['AuthorizationDetailsOnly']);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ScopeRepositoryInterface $scopeRepository = null,
    ): ScopeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpersStub;
        $scopeRepository ??= $this->scopeRepositoryStub;

        return new ScopeRule(
            $requestParamsResolver,
            $helpers,
            $scopeRepository,
            $this->moduleConfigStub,
        );
    }


    public function testConstruct(): void
    {
        $this->assertInstanceOf(ScopeRule::class, $this->sut());
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleStateDependency(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidScopes(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('openid profile');
        $this->strHelperMock->expects($this->once())->method('convertScopesStringToArray')
            ->with('openid profile')
            ->willReturn(['openid', 'profile']);
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturnOnConsecutiveCalls(
                $this->scopeEntities['openid'],
                $this->scopeEntities['profile'],
            );

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );
        $this->assertInstanceOf(Result::class, $result);
        $this->assertIsArray($result->getValue());
        $this->assertSame($this->scopeEntities['openid'], $result->getValue()[0]);
        $this->assertSame($this->scopeEntities['profile'], $result->getValue()[1]);
    }


    /**
     * @throws \Throwable
     */
    public function testInvalidScopeThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('openid');
        $this->strHelperMock->expects($this->once())->method('convertScopesStringToArray')
            ->with('openid')
            ->willReturn(['openid']);
        $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(null);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );
    }


    /**
     * A credential configuration whose metadata states no scope is requested through authorization_details only
     * (OpenID4VCI 1.0 section 12.2.4). Its id is a scope inside the module, so the repository knows it, but a
     * client may not ask for it: refused as a scope the server does not offer, to the redirect URI.
     *
     * @throws \Throwable
     */
    public function testRefusesTheIdOfACredentialConfigurationWithoutAScope(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('openid AuthorizationDetailsOnly');
        $this->strHelperMock->method('convertScopesStringToArray')
            ->willReturn(['openid', 'AuthorizationDetailsOnly']);
        $this->scopeRepositoryStub->method('getScopeEntityByIdentifier')
            ->willReturnCallback(fn(string $identifier): ScopeEntity => new ScopeEntity($identifier));

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $resultBag,
                $this->loggerServiceStub,
                $this->data,
                $this->responseModeStub,
            );
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_scope', $exception->getErrorType());
            $this->assertStringContainsString('AuthorizationDetailsOnly', (string)$exception->getHint());
            $this->assertSame('https://some-uri.org', $exception->getRedirectUri());

            return;
        }

        $this->fail('Expected the scope to be refused.');
    }


    /**
     * A credential configuration which states its id as its scope is requested by it like any other scope.
     *
     * @throws \Throwable
     */
    public function testAcceptsTheIdOfACredentialConfigurationWithAScope(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('ByScope');
        $this->strHelperMock->method('convertScopesStringToArray')->willReturn(['ByScope']);
        $scopeEntity = new ScopeEntity('ByScope');
        $this->scopeRepositoryStub->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );

        $this->assertSame([$scopeEntity], $result?->getValue());
    }


    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        return $resultBag;
    }


    protected function prepareValidScopeRepositoryStub(): InvocationStubber
    {
        return $this->scopeRepositoryStub
            ->method('getScopeEntityByIdentifier')
            ->willReturn(
                $this->onConsecutiveCalls(
                    $this->scopeEntities['openid'],
                    $this->scopeEntities['profile'],
                ),
            );
    }
}
