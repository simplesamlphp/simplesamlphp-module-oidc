<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules;

use LogicException;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager
 */
class RequestRulesManagerTest extends TestCase
{
    protected string $key = 'some-key';
    protected string $value = 'some-value';
    protected Stub $resultStub;
    protected Stub $ruleStub;
    protected Stub $request;


    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->resultStub = $this->createStub(ResultInterface::class);
        $this->resultStub->method('getKey')->willReturn($this->key);
        $this->resultStub->method('getValue')->willReturn($this->value);

        $this->ruleStub = $this->createStub(RequestRuleInterface::class);
        $this->ruleStub->method('getKey')->willReturn($this->key);
        $this->ruleStub->method('checkRule')->willReturn($this->resultStub);


        $this->request = $this->createStub(ServerRequestInterface::class);
    }

    public function testConstructWithoutRules(): RequestRulesManager
    {
        $requestRulesManager = new RequestRulesManager();
        $this->assertInstanceOf(RequestRulesManager::class, $requestRulesManager);

        return $requestRulesManager;
    }

    /**
     * @throws \Exception
     */
    public function testConstructWithRules(): void
    {
        $rules = [$this->createStub(RequestRuleInterface::class)];
        $this->assertInstanceOf(
            RequestRulesManager::class,
            new RequestRulesManager($rules),
        );
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testAddAndCheck(RequestRulesManager $requestRulesManager): void
    {
        $requestRulesManager->add($this->ruleStub);

        $resultBag = $requestRulesManager->check($this->request, [$this->key]);
        $this->assertInstanceOf(ResultBagInterface::class, $resultBag);

        $this->assertArrayHasKey($this->key, $resultBag->getAll());
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckWithNonExistingRuleKeyThrows(RequestRulesManager $requestRulesManager): void
    {
        $this->expectException(LogicException::class);
        $requestRulesManager->check($this->request, ['wrong-key']);
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testPredefineResult(RequestRulesManager $requestRulesManager): void
    {
        $requestRulesManager->predefineResult($this->resultStub);
        $resultBag = $requestRulesManager->check($this->request, []);

        $this->assertInstanceOf(ResultBagInterface::class, $resultBag);
        $this->assertArrayHasKey($this->key, $resultBag->getAll());
    }

    /**
     * @depends testConstructWithoutRules
     *
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
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
                $this->arrayHasKey($this->key),
            );

        $requestRulesManager->add($ruleMock);

        $requestRulesManager->check($this->request, [$this->key]);
    }
}
