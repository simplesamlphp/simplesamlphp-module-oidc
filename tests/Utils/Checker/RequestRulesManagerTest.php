<?php

namespace Tests\SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager;

/**
 * Class RequestRulesManagerTest
 * @covers \SimpleSAML\Modules\OpenIDConnect\Utils\Checker\RequestRulesManager
 */
class RequestRulesManagerTest extends TestCase
{
    protected $key = 'some-key';
    protected $value = 'some-value';
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
     * @return void
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
     * @return void
     */
    public function testCheckWithNonExistingRuleKeyThrows(RequestRulesManager $requestRulesManager): void
    {
        $this->expectException(\LogicException::class);
        $requestRulesManager->check($this->request, ['wrong-key']);
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @return void
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
     * @return void
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
                $this->arrayHasKey($this->key)
            );

        $requestRulesManager->add($ruleMock);

        $requestRulesManager->check($this->request, [$this->key]);
    }
}
