<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRedirectUriRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\StateRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\CodeChallengeMethodRule
 */
#[AllowMockObjectsWithoutExpectations]
class CodeChallengeMethodRuleTest extends TestCase
{
    protected CodeChallengeMethodRule $rule;

    protected Stub $requestStub;

    protected Stub $resultBagStub;

    protected Result $redirectUriResult;

    protected Result $stateResult;

    protected Stub $loggerServiceStub;

    protected Stub $requestParamsResolverStub;

    protected MockObject $codeChallengeVerifiersRepositoryMock;

    protected Helpers $helpers;

    protected Stub $responseModeStub;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->redirectUriResult = new Result(ClientRedirectUriRule::class, 'https://some-uri.org');
        $this->stateResult = new Result(StateRule::class, '123');
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->codeChallengeVerifiersRepositoryMock = $this->createMock(CodeChallengeVerifiersRepository::class);
        $this->helpers = new Helpers();
        $this->responseModeStub = $this->createStub(ResponseModeInterface::class);
    }


    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
        ?CodeChallengeVerifiersRepository $codeChallengeVerifiersRepository = null,
    ): CodeChallengeMethodRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;
        $codeChallengeVerifiersRepository ??= $this->codeChallengeVerifiersRepositoryMock;

        return new CodeChallengeMethodRule(
            $requestParamsResolver,
            $helpers,
            $codeChallengeVerifiersRepository,
        );
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
     */
    public function testCheckRuleWithInvalidCodeChallengeMethodThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('invalid');
        $this->codeChallengeVerifiersRepositoryMock->expects($this->once())->method('has')
            ->with('invalid')->willReturn(false);
        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub, [], $this->responseModeStub);
    }


    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleForValidCodeChallengeMethod(): void
    {
        $resultBag = $this->prepareValidResultBag();
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('plain');
        $this->codeChallengeVerifiersRepositoryMock->expects($this->once())->method('has')
            ->with('plain')->willReturn(true);
        $result = $this->sut()->checkRule(
            $this->requestStub,
            $resultBag,
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertInstanceOf(Result::class, $result);
        $this->assertSame('plain', $result->getValue());
    }


    /**
     * While issuance follows HAIP, an issuance request takes S256 only (FAPI 2.0 section 5.3.2.2): plain is refused,
     * and so is a request naming no method, which asks for plain. The resolver judges the request with the methods
     * the rule was given.
     *
     * @throws \Throwable
     */
    #[DataProvider('methodsOtherThanS256')]
    public function testRefusesAMethodOtherThanS256ForIssuanceFollowingHaip(?string $codeChallengeMethod): void
    {
        $requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $requestParamsResolverMock->method('getAsStringBasedOnAllowedMethods')->willReturn($codeChallengeMethod);
        $requestParamsResolverMock->expects($this->once())->method('isVciHaipIssuanceRequest')
            ->with($this->requestStub, [HttpMethodsEnum::POST])
            ->willReturn(true);
        $this->codeChallengeVerifiersRepositoryMock->method('has')->willReturn(true);

        try {
            $this->sut($requestParamsResolverMock)->checkRule(
                $this->requestStub,
                $this->prepareValidResultBag(),
                $this->loggerServiceStub,
                [],
                $this->responseModeStub,
                [HttpMethodsEnum::POST],
            );
            $this->fail('An issuance request following HAIP must use S256.');
        } catch (OidcServerException $exception) {
            $this->assertSame('invalid_request', $exception->getErrorType());
            $this->assertSame(400, $exception->getHttpStatusCode());
            $this->assertSame(
                'Code challenge method must be `S256` for credential issuance.',
                $exception->getHint(),
            );
            $this->assertSame('https://some-uri.org', $exception->getRedirectUri());
            $this->assertSame('123', $exception->getPayload()['state']);
        }
    }


    /**
     * @return array<string, array{?string}>
     */
    public static function methodsOtherThanS256(): array
    {
        return [
            'plain' => ['plain'],
            'none, which asks for plain' => [null],
            'S256 in lower case' => ['s256'],
        ];
    }


    /**
     * @throws \Throwable
     */
    public function testAcceptsS256ForIssuanceFollowingHaip(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('S256');
        $this->requestParamsResolverStub->method('isVciHaipIssuanceRequest')->willReturn(true);
        $this->codeChallengeVerifiersRepositoryMock->method('has')->willReturn(true);

        $result = $this->sut()->checkRule(
            $this->requestStub,
            $this->prepareValidResultBag(),
            $this->loggerServiceStub,
            [],
            $this->responseModeStub,
        );

        $this->assertSame('S256', $result?->getValue());
    }


    protected function prepareValidResultBag(): ResultBag
    {
        $resultBag = new ResultBag();
        $resultBag->add($this->redirectUriResult);
        $resultBag->add($this->stateResult);
        return $resultBag;
    }
}
