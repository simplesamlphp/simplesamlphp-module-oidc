<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Factories\ClaimTranslatorExtractorFactory;
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
     * @param string $derivedHost Host getIssuer() falls back to when the issuer is not configured.
     * @throws \Exception
     */
    protected function buildProtocolOverviewBuilder(
        array $overrides = [],
        string $derivedHost = 'https://derived-host.example.org',
    ): ProtocolOverviewBuilder {
        return new ProtocolOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides, $derivedHost),
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
            $this->buildClaimTranslatorExtractorFactory(),
        );
    }


    /**
     * A factory whose build() succeeds, so the translation table row shows a value.
     *
     * The builder takes the factory rather than a built extractor, because building one reads options
     * which can be malformed and doing that while the container wires the screen up is what took the
     * screen down. Tests which want that failure make build() throw instead.
     */
    protected function buildClaimTranslatorExtractorFactory(): ClaimTranslatorExtractorFactory
    {
        $factory = $this->createMock(ClaimTranslatorExtractorFactory::class);
        $factory->method('build')->willReturn($this->createMock(ClaimTranslatorExtractor::class));

        return $factory;
    }
}
