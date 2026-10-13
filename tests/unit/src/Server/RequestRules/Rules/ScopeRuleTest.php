<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\Builder\InvocationStubber;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Helpers\Str;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
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
     * Every scope value supported: nothing is ignored, so nothing is logged as ignored.
     *
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidScopes(): void
    {
        $this->loggerServiceStub = $this->createMock(LoggerService::class);
        $this->loggerServiceStub->expects($this->never())->method('notice');
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
     * A scope value the server does not support is ignored, not refused (OpenID4VCI 1.0 section 5.1.2, OpenID
     * Connect Core 1.0 section 3.1.2.1), wherever it stands among the others, and the log says which were
     * ignored, for which client.
     *
     * @throws \Throwable
     */
    public function testIgnoresTheScopeValuesItDoesNotSupport(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientNamed('client-id')));
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('unknown openid other-unknown profile');
        $this->strHelperMock->method('convertScopesStringToArray')
            ->willReturn(['unknown', 'openid', 'other-unknown', 'profile']);
        $this->scopeRepositoryStub->method('getScopeEntityByIdentifier')
            ->willReturnCallback(fn(string $identifier): ?ScopeEntity => $this->scopeEntities[$identifier] ?? null);
        $this->loggerServiceStub = $this->createMock(LoggerService::class);
        $this->loggerServiceStub->expects($this->once())->method('notice')->with(
            $this->stringContains('ignored'),
            ['client_id' => 'client-id', 'ignored_scopes' => ['unknown', 'other-unknown']],
        );

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );

        $this->assertSame([$this->scopeEntities['openid'], $this->scopeEntities['profile']], $result?->getValue());
    }


    /**
     * A request whose every scope value is ignored is left with none; whether that is enough is for the rules
     * which look at what is left (RequiredOpenIdScopeRule, OfferedCredentialsRule).
     *
     * @throws \Throwable
     */
    public function testIgnoresEveryScopeValueItDoesNotSupportLeavingNone(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('unknown');
        $this->strHelperMock->method('convertScopesStringToArray')->willReturn(['unknown']);
        $this->scopeRepositoryStub->method('getScopeEntityByIdentifier')->willReturn(null);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );

        $this->assertSame([], $result?->getValue());
    }


    /**
     * A credential configuration whose metadata states no scope is requested through authorization_details only
     * (OpenID4VCI 1.0 section 12.2.4). Its id is a scope inside the module, so the repository knows it, but it
     * is not one the server supports as a scope: ignored like any other such value.
     *
     * @throws \Throwable
     */
    public function testIgnoresTheIdOfACredentialConfigurationWithoutAScope(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')
            ->willReturn('openid AuthorizationDetailsOnly');
        $this->strHelperMock->method('convertScopesStringToArray')
            ->willReturn(['openid', 'AuthorizationDetailsOnly']);
        $this->scopeRepositoryStub->method('getScopeEntityByIdentifier')
            ->willReturnCallback(fn(string $identifier): ScopeEntity => new ScopeEntity($identifier));
        $this->loggerServiceStub = $this->createMock(LoggerService::class);
        $this->loggerServiceStub->expects($this->once())->method('notice')->with(
            $this->stringContains('ignored'),
            ['client_id' => null, 'ignored_scopes' => ['AuthorizationDetailsOnly']],
        );

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            $this->data,
            $this->responseModeStub,
        );

        $scopes = $result?->getValue();
        $this->assertIsArray($scopes);
        $this->assertSame(
            ['openid'],
            array_map(fn(ScopeEntity $scope): string => $scope->getIdentifier(), $scopes),
        );
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


    protected function clientNamed(string $clientId): ClientEntityInterface
    {
        $client = $this->createStub(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn($clientId);

        return $client;
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
