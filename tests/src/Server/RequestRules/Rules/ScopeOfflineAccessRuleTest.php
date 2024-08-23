<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Server\RequestRules\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeOfflineAccessRule;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * @covers \SimpleSAML\Module\oidc\Server\RequestRules\Rules\ScopeOfflineAccessRule
 */
class ScopeOfflineAccessRuleTest extends TestCase
{
    protected Stub $serverRequestStub;
    protected MockObject $resultBagMock;
    protected MockObject $loggerServiceMock;
    protected Stub $clientStub;
    protected Stub $scopeEntityOpenid;
    protected Stub $scopeEntityOfflineAccess;
    protected Stub $redirectUriResultStub;
    protected Stub $stateResultStub;
    protected Stub $clientResultStub;
    protected Stub $validScopesResultStub;
    protected Stub $moduleConfigStub;
    protected Stub $openIdConfigurationStub;

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->serverRequestStub = $this->createStub(ServerRequestInterface::class);
        $this->resultBagMock = $this->createMock(ResultBagInterface::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->clientStub = $this->createStub(ClientEntityInterface::class);

        $this->scopeEntityOpenid = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityOpenid->method('getIdentifier')->willReturn('openid');
        $this->scopeEntityOfflineAccess = $this->createStub(ScopeEntityInterface::class);
        $this->scopeEntityOfflineAccess->method('getIdentifier')->willReturn('offline_access');

        $this->redirectUriResultStub = $this->createStub(ResultInterface::class);
        $this->redirectUriResultStub->method('getValue')->willReturn('sample-uri');
        $this->stateResultStub = $this->createStub(ResultInterface::class);
        $this->stateResultStub->method('getValue')->willReturn('sample-state');

        $this->clientResultStub = $this->createStub(ResultInterface::class);
        $this->validScopesResultStub = $this->createStub(ResultInterface::class);

        $this->moduleConfigStub = $this->createStub(ModuleConfig::class);
        $this->openIdConfigurationStub = $this->createStub(Configuration::class);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ScopeOfflineAccessRule::class,
            new ScopeOfflineAccessRule(),
        );
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReturnsFalseWhenOfflineAccessScopeNotPresent(): void
    {
        $this->clientStub->method('getScopes')->willReturn(['openid']);
        $this->clientResultStub->method('getValue')->willReturn($this->clientStub);
        $this->validScopesResultStub->method('getValue')->willReturn([$this->scopeEntityOpenid]);

        $this->resultBagMock
            ->method('getOrFail')
            ->willReturnOnConsecutiveCalls(
                $this->redirectUriResultStub,
                $this->stateResultStub,
                $this->clientResultStub,
                $this->validScopesResultStub,
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->moduleConfigStub->method('config')
            ->willReturn($this->openIdConfigurationStub);

        $result = (new ScopeOfflineAccessRule())
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);

        $this->assertNotNull($result);
        $this->assertFalse($result->getValue());
    }

    /**
     * @throws \Throwable
     */
    public function testThrowsWhenClientDoesntHaveOfflineAccessScopeRegistered(): void
    {
        $this->clientStub->method('getScopes')->willReturn(['openid']);
        $this->clientResultStub->method('getValue')->willReturn($this->clientStub);
        $this->validScopesResultStub->method('getValue')
            ->willReturn([$this->scopeEntityOpenid, $this->scopeEntityOfflineAccess]);

        $this->resultBagMock
            ->method('getOrFail')
            ->willReturnOnConsecutiveCalls(
                $this->redirectUriResultStub,
                $this->stateResultStub,
                $this->clientResultStub,
                $this->validScopesResultStub,
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->moduleConfigStub->method('config')
            ->willReturn($this->openIdConfigurationStub);

        $this->expectException(OidcServerException::class);

        (new ScopeOfflineAccessRule())
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testReturnsTrueWhenClientDoesHaveOfflineAccessScopeRegistered(): void
    {
        $this->clientStub->method('getScopes')->willReturn(['openid', 'offline_access']);
        $this->clientResultStub->method('getValue')->willReturn($this->clientStub);
        $this->validScopesResultStub->method('getValue')
            ->willReturn([$this->scopeEntityOpenid, $this->scopeEntityOfflineAccess]);

        $this->resultBagMock
            ->method('getOrFail')
            ->willReturnOnConsecutiveCalls(
                $this->redirectUriResultStub,
                $this->stateResultStub,
                $this->clientResultStub,
                $this->validScopesResultStub,
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->moduleConfigStub->method('config')
            ->willReturn($this->openIdConfigurationStub);

        $result = (new ScopeOfflineAccessRule())
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);

        $this->assertNotNull($result);
        $this->assertTrue($result->getValue());
    }
}
