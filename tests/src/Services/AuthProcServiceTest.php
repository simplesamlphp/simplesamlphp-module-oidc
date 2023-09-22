<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\AuthProcService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthProcService
 */
class AuthProcServiceTest extends TestCase
{
    protected \PHPUnit\Framework\MockObject\MockObject $moduleConfigMock;

    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(\SimpleSAML\Module\oidc\ModuleConfig::class);
    }

    public function prepareMockedInstance(): AuthProcService
    {
        return new AuthProcService($this->moduleConfigMock);
    }

    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthProcService::class,
            $this->prepareMockedInstance()
        );
    }

    public function testItLoadsConfiguredFilters(): void
    {
        $this->moduleConfigMock->method('getAuthProcFilters')
            ->willReturn(['\SimpleSAML\Module\core\Auth\Process\AttributeAdd',]);

        $authProcService = $this->prepareMockedInstance();
        $this->assertIsArray($authProcService->getLoadedFilters());
        $this->assertCount(1, $authProcService->getLoadedFilters());
    }

    public function testItExecutesConfiguredFilters(): void
    {
        $sampleFilters = [
            50 => [
                'class' => '\SimpleSAML\Module\core\Auth\Process\AttributeAdd',
                'newKey' => ['newValue']
            ],
        ];
        $this->moduleConfigMock->method('getAuthProcFilters')->willReturn($sampleFilters);

        $state = ['Attributes' => ['existingKey' => ['existingValue']]];

        $authProcService = $this->prepareMockedInstance();

        $newState = $authProcService->processState($state);

        $this->assertArrayHasKey('newKey', $newState['Attributes']);
        $this->assertTrue(in_array('newValue', $newState['Attributes']['newKey']));
    }
}
