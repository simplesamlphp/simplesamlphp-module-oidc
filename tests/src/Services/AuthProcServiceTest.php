<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Services;

use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Framework\MockObject\MockObject;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\core\Auth\Process\AttributeAdd;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Services\AuthProcService;

/**
 * @covers \SimpleSAML\Module\oidc\Services\AuthProcService
 */
class AuthProcServiceTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    /**
     * @throws Exception
     */
    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
    }

    /**
     * @throws \Exception
     */
    public function prepareMockedInstance(): AuthProcService
    {
        return new AuthProcService($this->moduleConfigMock);
    }

    /**
     * @throws \Exception
     */
    public function testItIsInitializable(): void
    {
        $this->assertInstanceOf(
            AuthProcService::class,
            $this->prepareMockedInstance()
        );
    }

    /**
     * @throws \Exception
     */
    public function testItLoadsConfiguredFilters(): void
    {
        $this->moduleConfigMock->method('getAuthProcFilters')
            ->willReturn(['\\' . AttributeAdd::class,]);

        $authProcService = $this->prepareMockedInstance();
        $this->assertIsArray($authProcService->getLoadedFilters());
        $this->assertCount(1, $authProcService->getLoadedFilters());
    }

    /**
     * @throws \Exception
     */
    public function testItExecutesConfiguredFilters(): void
    {
        $sampleFilters = [
            50 => [
                'class' => '\\' . AttributeAdd::class,
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
