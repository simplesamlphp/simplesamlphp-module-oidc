<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ScopeEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RequiredOpenIdScopeRule
 */
#[AllowMockObjectsWithoutExpectations]
class RequiredOpenIdScopeRuleTest extends TestCase
{
    protected array $scopeEntities = [];

    protected Result $redirectUriResult;

    protected Result $stateResult;

    protected Result $scopeResult;

    protected Stub $requestStub;

    protected Stub $loggerServiceStub;

    protected Stub $requestParamsResolverStub;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->redirectUriResult = new Result(ClientRedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->scopeEntities = [
            'openid' => new ScopeEntity('openid'),
            'profile' => new ScopeEntity('profile'),
        ];
        $this->scopeResult = new Result(ScopeRule::class, $this->scopeEntities);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ModuleConfig $moduleConfig = null,
    ): RequiredOpenIdScopeRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $moduleConfig ??= $this->moduleConfig(plainOAuth2AuthorizationCodeEnabled: false);

        return new RequiredOpenIdScopeRule(
            $requestParamsResolver,
            $helpers,
            $moduleConfig,
        );
    }


    protected function moduleConfig(bool $plainOAuth2AuthorizationCodeEnabled): ModuleConfig
    {
        $moduleConfig = $this->createStub(ModuleConfig::class);
        $moduleConfig->method('isPlainOAuth2AuthorizationCodeEnabled')
            ->willReturn($plainOAuth2AuthorizationCodeEnabled);

        return $moduleConfig;
    }


    protected function resultBagWithoutTheOpenIdScope(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add(new Result(ScopeRule::class, ['profile' => new ScopeEntity('profile')]));

        return $resultBag;
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleRedirectUriDependency(): void
    {
        $resultBag = new ResultBag();
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
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
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRulePassesWhenOpenIdScopeIsPresent()
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add($this->scopeResult);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        ) ??
        new Result(RequiredOpenIdScopeRule::class, null);

        $this->assertTrue($result->getValue());
    }


    /**
     * @throws \Throwable
     */
    public function testCheckRuleThrowsWhenOpenIdScopeIsNotPresent()
    {
        // A plain OAuth 2.0 code request among them, since they are not enabled by default: refused as an invalid
        // request, sent back to the client's redirect URI.
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('code');

        try {
            $this->sut()->checkRule(
                $this->requestStub,
                $this->resultBagWithoutTheOpenIdScope(),
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
            $this->fail('A request without the openid scope was let through.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('https://some-uri.org', $exception->getRedirectUri());
        }
    }


    /**
     * An OpenID4VCI authorization code request need not carry openid. Whether a request is one is the
     * resolver's call, made from the methods the rule is allowed to read, and with the broad detection:
     * a wallet starting the flow on its own carries no issuer_state.
     *
     * @throws \Throwable
     */
    public function testCheckRulePassesWithoutOpenIdScopeForAVciRequest(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        $resultBag->add(new Result(ScopeRule::class, ['ResearchCredential' => new ScopeEntity('ResearchCredential')]));
        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->expects($this->once())->method('isVciAuthorizationCodeRequest')
            ->with($this->identicalTo($this->requestStub), [HttpMethodsEnum::POST])
            ->willReturn(true);
        $requestParamsResolverMock->expects($this->never())->method('isVciAuthorizationCodeRequestWithIssuerState');

        $result = $this->sut($requestParamsResolverMock)->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
            [HttpMethodsEnum::POST],
        );

        $this->assertTrue($result?->getValue());
    }


    /**
     * A plain OAuth 2.0 authorization code request, which asks for neither the openid scope nor a credential, is
     * let through where the deployment enables such requests. Its response type is read from the methods the rule
     * is allowed to read.
     *
     * @throws \Throwable
     */
    public function testLetsAPlainOAuth2CodeRequestThroughWhereSuchRequestsAreEnabled(): void
    {
        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->method('isVciAuthorizationCodeRequest')->willReturn(false);
        $requestParamsResolverMock->expects($this->once())->method('getAsStringBasedOnAllowedMethods')
            ->with(ParamsEnum::ResponseType->value, $this->identicalTo($this->requestStub), [HttpMethodsEnum::POST])
            ->willReturn('code');

        $result = $this->sut(
            $requestParamsResolverMock,
            moduleConfig: $this->moduleConfig(plainOAuth2AuthorizationCodeEnabled: true),
        )->checkRule(
            $this->requestStub,
            $this->resultBagWithoutTheOpenIdScope(),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
            [HttpMethodsEnum::POST],
        );

        $this->assertTrue($result?->getValue());
    }


    /**
     * @return array<string, array{0: bool, 1: ?string}>
     */
    public static function noEnabledPlainOAuth2CodeRequestProvider(): array
    {
        return [
            'a code request where plain OAuth 2.0 ones are not enabled' => [false, 'code'],
            'an implicit request, which delivers an ID token' => [true, 'id_token'],
            'an implicit request for an ID token and an access token' => [true, 'id_token token'],
            'a hybrid request' => [true, 'code id_token'],
            'a request without a response type' => [true, null],
        ];
    }


    /**
     * Only a request for the code response type is a plain OAuth 2.0 one the deployment may enable: the implicit
     * grant's response types deliver an ID token, which only an OpenID Connect request can ask for.
     *
     * @throws \Throwable
     */
    #[DataProvider('noEnabledPlainOAuth2CodeRequestProvider')]
    public function testRefusesARequestWithoutTheOpenIdScopeWhichIsNoEnabledPlainOAuth2CodeRequest(
        bool $plainOAuth2AuthorizationCodeEnabled,
        ?string $responseType,
    ): void {
        $requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $requestParamsResolverStub->method('isVciAuthorizationCodeRequest')->willReturn(false);
        $requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($responseType);

        $this->expectException(OidcServerException::class);

        $this->sut(
            $requestParamsResolverStub,
            moduleConfig: $this->moduleConfig($plainOAuth2AuthorizationCodeEnabled),
        )->checkRule(
            $this->requestStub,
            $this->resultBagWithoutTheOpenIdScope(),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }
}
