<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

/**
 * Builds a ProtocolOverviewBuilder for tests. Requires OverviewTestTrait.
 */
trait ProtocolOverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @throws \Exception
     */
    protected function buildProtocolOverviewBuilder(array $overrides = []): ProtocolOverviewBuilder
    {
        return new ProtocolOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
            $this->createMock(ClaimTranslatorExtractor::class),
        );
    }
}
