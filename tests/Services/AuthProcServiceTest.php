<?php

namespace SimpleSAML\Test\Module\oidc\Services;

use SimpleSAML\Module\oidc\Services\AuthProcService;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\ConfigurationService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthProcService
 */
class AuthProcServiceTest extends TestCase
{
    protected \PHPUnit\Framework\MockObject\MockObject $configurationServiceMock;

    protected function setUp(): void
    {
        $this->configurationServiceMock = $this->createMock(ConfigurationService::class);
    }

    public function prepareMockedInstance(): AuthProcService
    {
        return new AuthProcService($this->configurationServiceMock);
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
        $this->configurationServiceMock->method('getAuthProcFilters')
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
        $this->configurationServiceMock->method('getAuthProcFilters')->willReturn($sampleFilters);

        $state = ['Attributes' => ['existingKey' => ['existingValue']]];

        $authProcService = $this->prepareMockedInstance();

        $newState = $authProcService->processState($state);

        $this->assertArrayHasKey('newKey', $newState['Attributes']);
        $this->assertTrue(in_array('newValue', $newState['Attributes']['newKey']));
    }
}
