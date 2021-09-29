<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker;

use LogicException;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager;

/**
 * Class RequestRulesManagerTest
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\RequestRulesManager
 */
class RequestRulesManagerTest extends TestCase
{
    protected string $key = 'some-key';
    protected string $value = 'some-value';
    protected $result;
    protected $rule;
    protected $request;


    public function setUp(): void
    {
        $this->result = $this->createStub(ResultInterface::class);
        $this->result->method('getKey')->willReturn($this->key);
        $this->result->method('getValue')->willReturn($this->value);

        $this->rule = $this->createStub(RequestRuleInterface::class);
        $this->rule->method('getKey')->willReturn($this->key);
        $this->rule->method('checkRule')->willReturn($this->result);


        $this->request = $this->createStub(ServerRequestInterface::class);
    }

    public function testConstructWithoutRules(): RequestRulesManager
    {
        $requestRulesManager = new RequestRulesManager();
        $this->assertInstanceOf(RequestRulesManager::class, $requestRulesManager);

        return $requestRulesManager;
    }

    public function testConstructWithRules(): void
    {
        $rules = [$this->createStub(RequestRuleInterface::class)];
        $this->assertInstanceOf(RequestRulesManager::class, new RequestRulesManager($rules));
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @param RequestRulesManager $requestRulesManager
     * @return void
     * @throws OidcServerException
     */
    public function testAddAndCheck(RequestRulesManager $requestRulesManager): void
    {
        $requestRulesManager->add($this->rule);

        $resultBag = $requestRulesManager->check($this->request, [$this->key]);
        $this->assertInstanceOf(ResultBagInterface::class, $resultBag);

        $this->assertArrayHasKey($this->key, $resultBag->getAll());
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @param RequestRulesManager $requestRulesManager
     * @return void
     * @throws OidcServerException
     */
    public function testCheckWithNonExistingRuleKeyThrows(RequestRulesManager $requestRulesManager): void
    {
        $this->expectException(LogicException::class);
        $requestRulesManager->check($this->request, ['wrong-key']);
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @param RequestRulesManager $requestRulesManager
     * @return void
     * @throws OidcServerException
     */
    public function testPredefineResult(RequestRulesManager $requestRulesManager): void
    {
        $requestRulesManager->predefineResult($this->result);
        $resultBag = $requestRulesManager->check($this->request, []);

        $this->assertInstanceOf(ResultBagInterface::class, $resultBag);
        $this->assertArrayHasKey($this->key, $resultBag->getAll());
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @param RequestRulesManager $requestRulesManager
     * @return void
     * @throws OidcServerException
     */
    public function testSetData(RequestRulesManager $requestRulesManager): void
    {
        $requestRulesManager->setData($this->key, $this->value);

        $ruleMock = $this->createMock(RequestRuleInterface::class);
        $ruleMock->method('getKey')->willReturn($this->key);
        $ruleMock->expects($this->once())
            ->method('checkRule')
            ->with(
                $this->identicalTo($this->request),
                $this->isInstanceOf(ResultBagInterface::class),
                $this->isInstanceOf(LoggerService::class),
                $this->arrayHasKey($this->key)
            );

        $requestRulesManager->add($ruleMock);

        $requestRulesManager->check($this->request, [$this->key]);
    }
}
