<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\FederationOverviewBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

/**
 * Builds a FederationOverviewBuilder for tests. Requires OverviewTestTrait.
 */
trait FederationOverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @throws \Exception
     */
    protected function buildFederationOverviewBuilder(array $overrides = []): FederationOverviewBuilder
    {
        return new FederationOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
        );
    }
}
