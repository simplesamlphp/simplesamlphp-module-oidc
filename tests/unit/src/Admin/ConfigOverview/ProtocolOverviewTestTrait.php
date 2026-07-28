<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Row;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

/**
 * Shared wiring for tests which need a ProtocolOverviewBuilder backed by the real module config
 * from tests/config/module_oidc.php.
 */
trait ProtocolOverviewTestTrait
{
    /**
     * Build the system under test, optionally overriding module config options.
     *
     * @param array $overrides
     * @throws \Exception
     */
    protected function buildProtocolOverviewBuilder(array $overrides = []): ProtocolOverviewBuilder
    {
        $sspBridgeUtilsConfigMock = $this->createMock(Config::class);
        $sspBridgeUtilsConfigMock->method('getCertPath')
            ->willReturnCallback(
                fn(string $filename): string => dirname(__DIR__, 4) . '/cert/' . $filename,
            );

        // Used when the issuer is not explicitly configured, in which case it is derived from the
        // current HTTP host.
        $sspBridgeUtilsHttpMock = $this->createMock(HTTP::class);
        $sspBridgeUtilsHttpMock->method('getSelfURLHost')->willReturn('https://derived-host.example.org');

        $sspBridgeUtilsMock = $this->createMock(SspBridge\Utils::class);
        $sspBridgeUtilsMock->method('config')->willReturn($sspBridgeUtilsConfigMock);
        $sspBridgeUtilsMock->method('http')->willReturn($sspBridgeUtilsHttpMock);

        $sspBridgeMock = $this->createMock(SspBridge::class);
        $sspBridgeMock->method('utils')->willReturn($sspBridgeUtilsMock);

        $moduleConfig = new ModuleConfig(
            ModuleConfig::DEFAULT_FILE_NAME,
            $overrides,
            $this->createMock(Configuration::class),
            $sspBridgeMock,
            $this->createMock(ValueAbstracts::class),
        );

        return new ProtocolOverviewBuilder(
            $moduleConfig,
            $this->createMock(Routes::class),
            new DateIntervalFormatter(),
            $this->createMock(ClaimTranslatorExtractor::class),
        );
    }

    /**
     * Flatten all rows of the given sections.
     *
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Row[]
     */
    protected function flattenRows(array $sections): array
    {
        $rows = [];

        foreach ($sections as $section) {
            $this->assertInstanceOf(Section::class, $section);
            foreach ($section->getRows() as $row) {
                $rows[] = $row;
            }
        }

        return $rows;
    }

    /**
     * Find the row which displays the given ModuleConfig::OPTION_* value.
     *
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     */
    protected function findRowForOption(array $sections, string $configOption): ?Row
    {
        foreach ($this->flattenRows($sections) as $row) {
            if ($row->getConfigOption() === $configOption) {
                return $row;
            }
        }

        return null;
    }

    /**
     * All displayable (scalar or array) row content, as one searchable string. Used to assert that
     * secrets never reach the screen.
     *
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     */
    protected function renderableContent(array $sections): string
    {
        $content = '';

        foreach ($this->flattenRows($sections) as $row) {
            $content .= $row->getLabel() . ' ' . $row->getNote() . ' ' . $row->getWarning() . ' ';

            /** @var mixed $value */
            $value = $row->getValue();

            if (is_scalar($value) || is_array($value)) {
                $content .= var_export($value, true) . ' ';
            }
        }

        return $content;
    }
}
