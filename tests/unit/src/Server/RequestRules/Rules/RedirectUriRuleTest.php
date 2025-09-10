<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\RequestRules\Rules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\RequestRules\ResultBag;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\RedirectUriRule
 */
class RedirectUriRuleTest extends TestCase
{
    protected RedirectUriRule $rule;
    protected ResultBag $resultBag;
    protected Stub $clientStub;
    protected Stub $requestStub;
    protected string $redirectUri = 'https://some-redirect-uri.org';
    protected Stub $loggerServiceStub;
    protected Stub $requestParamsResolverStub;
    protected Helpers $helpers;


    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->loggerServiceStub = $this->createStub(LoggerService::class);
        $this->requestParamsResolverStub = $this->createStub(RequestParamsResolver::class);
        $this->helpers = new Helpers();
    }

    protected function sut(
        ?RequestParamsResolver $requestParamsResolver = null,
        ?Helpers $helpers = null,
    ): RedirectUriRule {
        $requestParamsResolver ??= $this->requestParamsResolverStub;
        $helpers ??= $this->helpers;

        return new RedirectUriRule(
            $requestParamsResolver,
            $helpers,
        );
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleClientIdDependency(): void
    {
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleWithInvalidClientDependancy(): void
    {
        $this->resultBag->add(new Result(ClientRule::class, 'invalid'));
        $this->expectException(LogicException::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleRedirectUriNotSetThrows(): void
    {
        $resultBag = $this->prepareValidResultBag();

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleDifferentClientRedirectUriThrows(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('invalid');
        $resultBag = $this->prepareValidResultBag();

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     */
    public function testCheckRuleDifferentClientRedirectUriArrayThrows(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn('invalid');

        $this->clientStub->method('getRedirectUri')->willReturn([$this->redirectUri]);
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));

        $this->expectException(OidcServerException::class);
        $this->sut()->checkRule($this->requestStub, $this->resultBag, $this->loggerServiceStub);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleWithValidRedirectUri(): void
    {
        $this->requestParamsResolverStub->method('getAsStringBasedOnAllowedMethods')->willReturn($this->redirectUri);

        $resultBag = $this->prepareValidResultBag();

        $result = $this->sut()->checkRule($this->requestStub, $resultBag, $this->loggerServiceStub);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($this->redirectUri, $result->getValue());
    }

    protected function prepareValidResultBag(): ResultBag
    {
        $this->clientStub->method('getRedirectUri')->willReturn($this->redirectUri);
        $this->resultBag->add(new Result(ClientRule::class, $this->clientStub));
        return $this->resultBag;
    }
}
