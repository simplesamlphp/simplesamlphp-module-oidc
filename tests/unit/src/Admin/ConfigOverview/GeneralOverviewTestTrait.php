<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\GeneralOverviewBuilder;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

/**
 * Builds a GeneralOverviewBuilder for tests. Requires OverviewTestTrait.
 */
trait GeneralOverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @param bool $isCronModuleEnabled Whether the SimpleSAMLphp cron module is enabled.
     * @param mixed $allowedCronTags Value of the cron module's 'allowed_tags' option. Defaults to
     *                               what the cron module ships with. Null leaves the tags unlimited.
     * @throws \Exception
     */
    protected function buildGeneralOverviewBuilder(
        array $overrides = [],
        bool $isCronModuleEnabled = true,
        mixed $allowedCronTags = ['daily', 'hourly', 'frequent'],
    ): GeneralOverviewBuilder {
        $sspBridgeModuleMock = $this->createMock(SspBridge\Module::class);
        $sspBridgeModuleMock->method('isModuleEnabled')->willReturn($isCronModuleEnabled);
        $sspBridgeModuleMock->method('getOptionalConfig')->willReturn(
            Configuration::loadFromArray(['allowed_tags' => $allowedCronTags]),
        );

        $sspBridgeMock = $this->createMock(SspBridge::class);
        $sspBridgeMock->method('module')->willReturn($sspBridgeModuleMock);

        return new GeneralOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
            $sspBridgeMock,
        );
    }
}
