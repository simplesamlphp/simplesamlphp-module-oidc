<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use ErrorException;
use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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

#[CoversClass(ResponseModeRule::class)]
#[AllowMockObjectsWithoutExpectations]
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


    #[DataProvider('tokenResponseTypeProvider')]
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


    /**
     * The rule under a handler which makes a warning an exception, so that a cast of a value which is not a string
     * fails the test instead of passing with a warning beside it.
     */
    protected function checkRuleWithoutWarnings(array $params): ?Result
    {
        $this->requestParamsResolverStub->method('getAllBasedOnAllowedMethods')->willReturn($params);

        set_error_handler(static function (int $severity, string $message): never {
            throw new ErrorException($message, 0, $severity);
        });

        try {
            return $this->sut()->checkRule(
                $this->requestStub,
                $this->resultBag,
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
            );
        } finally {
            restore_error_handler();
        }
    }


    /**
     * A response type which is not a string - an array from the query, a number from a Request Object - is read as
     * none when the default response mode is chosen, with no warning: ResponseTypeRule refuses it after this rule.
     */
    #[DataProvider('valueWhichIsNotAStringProvider')]
    public function testReadsAResponseTypeWhichIsNotAStringAsNone(mixed $responseType): void
    {
        $result = $this->checkRuleWithoutWarnings(['client_id' => 'client123', 'response_type' => $responseType]);

        $this->assertSame($this->queryResponseModeStub, $result?->getValue());
    }


    /**
     * A response mode which is not a string is refused as one which is not supported, with no warning, rather than
     * cast to one.
     */
    #[DataProvider('valueWhichIsNotAStringProvider')]
    public function testRefusesAResponseModeWhichIsNotAString(mixed $responseMode): void
    {
        try {
            $this->checkRuleWithoutWarnings(
                ['client_id' => 'client123', 'response_type' => 'code', 'response_mode' => $responseMode],
            );
            $this->fail('A response mode which is not a string was accepted.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame('Invalid response_mode', $exception->getHint());
        }
    }


    public static function valueWhichIsNotAStringProvider(): array
    {
        return [
            'an array' => [['query']],
            'a number' => [1],
        ];
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
