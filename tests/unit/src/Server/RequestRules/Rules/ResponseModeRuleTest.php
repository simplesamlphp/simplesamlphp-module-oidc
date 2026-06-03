<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ResponseModeRule
 */
class ResponseModeRuleTest extends TestCase
{
    protected Stub $requestStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;
    protected ResultBag $resultBag;
    protected Stub $loggerServiceStub;
    protected Stub $responseModeStub;
    protected Stub $clientStub;
    protected Stub $queryResponseModeStub;
    protected Stub $fragmentResponseModeStub;
    protected Stub $formPostResponseModeStub;
    protected Stub $moduleConfigStub;

    protected array $requestParams = [
        'client_id' => 'client123',
        'response_type' => 'code',
        'response_mode' => 'query',
    ];

    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);

        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->clientStub->method('getAllowedResponseModes')->willReturn(['query', 'fragment', 'form_post']);

        $this->queryResponseModeStub = $this->createStub(QueryResponseMode::class);
        $this->fragmentResponseModeStub = $this->createStub(FragmentResponseMode::class);
        $this->formPostResponseModeStub = $this->createStub(FormPostResponseMode::class);

        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->moduleConfigStub->method('getSupportedResponseModes')->willReturn(['query', 'fragment', 'form_post']);

        $this->resultBag = new ResultBag();
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://example.org/callback'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?ModuleConfig $moduleConfig = null,
        ?QueryResponseMode $queryResponseMode = null,
        ?FragmentResponseMode $fragmentResponseMode = null,
        ?FormPostResponseMode $formPostResponseMode = null,
    ): ResponseModeRule {
        return new ResponseModeRule(
            $requestParamsResolver ?? $this->requestParamsResolverStub,
            $helpers ?? $this->helpers,
            $moduleConfig ?? $this->moduleConfigStub,
            $queryResponseMode ?? $this->queryResponseModeStub,
            $fragmentResponseMode ?? $this->fragmentResponseModeStub,
            $formPostResponseMode ?? $this->formPostResponseModeStub,
        );
    }

    public function testThrowsWhenClientIdMissing(): void
    {
        $params = $this->requestParams;
        unset($params['client_id']);
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testReturnsQueryResponseModeWhenExplicitlyRequested(): void
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->queryResponseModeStub, $result->getValue());
    }

    public function testReturnsFragmentResponseModeWhenExplicitlyRequested(): void
    {
        $params = $this->requestParams;
        $params['response_mode'] = 'fragment';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->fragmentResponseModeStub, $result->getValue());
    }

    public function testReturnsFormPostResponseModeWhenExplicitlyRequested(): void
    {
        $params = $this->requestParams;
        $params['response_mode'] = 'form_post';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->formPostResponseModeStub, $result->getValue());
    }

    public function testDefaultsToQueryWhenResponseModeNotSetAndResponseTypeIsCode(): void
    {
        $params = $this->requestParams;
        unset($params['response_mode']);
        $params['response_type'] = 'code';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->queryResponseModeStub, $result->getValue());
    }

    /**
     * @dataProvider tokenResponseTypeProvider
     */
    public function testDefaultsToFragmentWhenResponseModeNotSetAndResponseTypeContainsToken(
        string $responseType,
    ): void {
        $params = $this->requestParams;
        unset($params['response_mode']);
        $params['response_type'] = $responseType;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->fragmentResponseModeStub, $result->getValue());
    }

    public static function tokenResponseTypeProvider(): array
    {
        return [
            'token' => ['token'],
            'id_token token' => ['id_token token'],
            'code token' => ['code token'],
            'code id_token token' => ['code id_token token'],
        ];
    }

    public function testDefaultsToQueryWhenResponseModeAndResponseTypeNotSet(): void
    {
        $params = ['client_id' => 'client123'];
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame($this->queryResponseModeStub, $result->getValue());
    }

    public function testThrowsOnInvalidResponseMode(): void
    {
        $params = $this->requestParams;
        $params['response_mode'] = 'invalid';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsWhenResponseModeNotAllowedByClient(): void
    {
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->clientStub->method('getAllowedResponseModes')->willReturn(['query']);

        $this->resultBag = new ResultBag();
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $this->resultBag->add(new Result(ClientRedirectUriRule::class, 'https://example.org/callback'));
        $this->resultBag->add(new Result(StateRule::class, 'state123'));

        $params = $this->requestParams;
        $params['response_mode'] = 'fragment';
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsWhenClientRuleResultMissing(): void
    {
        $resultBag = new ResultBag();

        $params = $this->requestParams;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsWhenRedirectUriResultMissing(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientStub));

        $params = $this->requestParams;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testThrowsWhenStateResultMissing(): void
    {
        $resultBag = new ResultBag();
        $resultBag->add(new Result(ClientRule::class, $this->clientStub));
        $resultBag->add(new Result(ClientRedirectUriRule::class, 'https://example.org/callback'));

        $params = $this->requestParams;
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        $this->expectException(LogicException::class);
        $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );
    }

    public function testResultKeyMatchesRuleClass(): void
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($this->requestParams);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertNotNull($result);
        $this->assertSame(ResponseModeRule::class, $result->getKey());
    }
}
