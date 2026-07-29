<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

/**
 * Builds a VciOverviewBuilder for tests. Requires OverviewTestTrait.
 */
trait VciOverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @throws \Exception
     */
    protected function buildVciOverviewBuilder(array $overrides = []): VciOverviewBuilder
    {
        return new VciOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
        );
    }
}
