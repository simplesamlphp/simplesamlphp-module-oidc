<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\ResultBag;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ClientIdRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\RedirectUriRule
 */
class RedirectUriRuleTest extends TestCase
{
    protected $rule;
    protected $resultBag;
    protected $clientStub;
    protected $request;
    protected $redirectUri = 'https://some-redirect-uri.org';


    protected function setUp(): void
    {
        $this->rule = new RedirectUriRule();
        $this->resultBag = new ResultBag();
        $this->clientStub = $this->createStub(ClientEntityInterface::class);
        $this->request = $this->createStub(ServerRequestInterface::class);
    }

    public function testCheckRuleClientIdDependancy(): void
    {
        $this->expectException(\LogicException::class);
        $this->rule->checkRule($this->request, $this->resultBag, []);
    }

    public function testCheckRuleWithInvalidClientDependancy(): void
    {
        $this->resultBag->add(new Result(ClientIdRule::class, 'invalid'));
        $this->expectException(\LogicException::class);
        $this->rule->checkRule($this->request, $this->resultBag, []);
    }

    public function testCheckRuleRedirectUriNotSetThrows(): void
    {
        $this->request->method('getQueryParams')->willReturn([]);
        $resultBag = $this->prepareValidResultBag();

        $this->expectException(OidcServerException::class);
        $this->rule->checkRule($this->request, $resultBag, []);
    }

    public function testCheckRuleDifferentClientRedirectUriThrows(): void
    {
        $this->request->method('getQueryParams')->willReturn(['redirect_uri' => 'invalid']);
        $resultBag = $this->prepareValidResultBag();

        $this->expectException(OidcServerException::class);
        $this->rule->checkRule($this->request, $resultBag, []);
    }

    public function testCheckRuleDifferentClientRedirectUriArrayThrows(): void
    {
        $this->request->method('getQueryParams')->willReturn(['redirect_uri' => 'invalid']);

        $this->clientStub->method('getRedirectUri')->willReturn([$this->redirectUri]);
        $this->resultBag->add(new Result(ClientIdRule::class, $this->clientStub));

        $this->expectException(OidcServerException::class);
        $this->rule->checkRule($this->request, $this->resultBag, []);
    }

    public function testCheckRuleWithValidRedirectUri(): void
    {
        $this->request->method('getQueryParams')->willReturn(['redirect_uri' => $this->redirectUri]);
        $resultBag = $this->prepareValidResultBag();

        $result = $this->rule->checkRule($this->request, $resultBag, []);

        $this->assertInstanceOf(ResultInterface::class, $result);
        $this->assertSame($this->redirectUri, $result->getValue());
    }

    protected function prepareValidResultBag()
    {
        $this->clientStub->method('getRedirectUri')->willReturn($this->redirectUri);
        $this->resultBag->add(new Result(ClientIdRule::class, $this->clientStub));
        return $this->resultBag;
    }
}
