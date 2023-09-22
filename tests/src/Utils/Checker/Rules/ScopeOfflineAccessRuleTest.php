<?php

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\ConfigurationService;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeOfflineAccessRule;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\ScopeOfflineAccessRule
 */
class ScopeOfflineAccessRuleTest extends TestCase
{
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $serverRequestStub;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $resultBagMock;
    /**
     * @var \PHPUnit\Framework\MockObject\MockObject
     */
    protected $loggerServiceMock;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $clientStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $scopeEntityOpenid;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $scopeEntityOfflineAccess;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $redirectUriResultStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $stateResultStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $clientResultStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $validScopesResultStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $configurationServiceStub;
    /**
     * @var \PHPUnit\Framework\MockObject\Stub
     */
    protected $openIdConfigurationStub;

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

        $this->configurationServiceStub = $this->createStub(ConfigurationService::class);
        $this->openIdConfigurationStub = $this->createStub(Configuration::class);
    }

    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(
            ScopeOfflineAccessRule::class,
            new ScopeOfflineAccessRule($this->configurationServiceStub)
        );
    }

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
                $this->validScopesResultStub
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->configurationServiceStub->method('getOpenIDConnectConfiguration')
            ->willReturn($this->openIdConfigurationStub);

        $result = (new ScopeOfflineAccessRule($this->configurationServiceStub))
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);

        $this->assertNotNull($result);
        $this->assertFalse($result->getValue());
    }

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
                $this->validScopesResultStub
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->configurationServiceStub->method('getOpenIDConnectConfiguration')
            ->willReturn($this->openIdConfigurationStub);

        $this->expectException(OidcServerException::class);

        (new ScopeOfflineAccessRule($this->configurationServiceStub))
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);
    }

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
                $this->validScopesResultStub
            );

        $this->openIdConfigurationStub->method('getBoolean')->willReturn(false);
        $this->configurationServiceStub->method('getOpenIDConnectConfiguration')
            ->willReturn($this->openIdConfigurationStub);

        $result = (new ScopeOfflineAccessRule($this->configurationServiceStub))
            ->checkRule($this->serverRequestStub, $this->resultBagMock, $this->loggerServiceMock);

        $this->assertNotNull($result);
        $this->assertTrue($result->getValue());
    }
}
