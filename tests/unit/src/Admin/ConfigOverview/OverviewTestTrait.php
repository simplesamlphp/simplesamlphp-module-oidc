<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Row;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\ValueAbstracts;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

/**
 * Wiring shared by the configuration overview tests: a real ModuleConfig backed by
 * tests/config/module_oidc.php, plus helpers for inspecting the produced sections.
 */
trait OverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @param string $derivedHost Host getIssuer() falls back to when the issuer is not configured.
     *                            An empty string makes it throw, which the screens must survive.
     * @throws \Exception
     */
    protected function buildOverviewModuleConfig(
        array $overrides = [],
        string $derivedHost = 'https://derived-host.example.org',
    ): ModuleConfig {
        $sspBridgeUtilsConfigMock = $this->createMock(Config::class);
        $sspBridgeUtilsConfigMock->method('getCertPath')
            ->willReturnCallback(
                fn(string $filename): string => dirname(__DIR__, 4) . '/cert/' . $filename,
            );

        // Used when the issuer is not explicitly configured, in which case it is derived from the
        // current HTTP host.
        $sspBridgeUtilsHttpMock = $this->createMock(HTTP::class);
        $sspBridgeUtilsHttpMock->method('getSelfURLHost')->willReturn($derivedHost);

        $sspBridgeUtilsMock = $this->createMock(Utils::class);
        $sspBridgeUtilsMock->method('config')->willReturn($sspBridgeUtilsConfigMock);
        $sspBridgeUtilsMock->method('http')->willReturn($sspBridgeUtilsHttpMock);

        $sspBridgeMock = $this->createMock(SspBridge::class);
        $sspBridgeMock->method('utils')->willReturn($sspBridgeUtilsMock);

        return new ModuleConfig(
            ModuleConfig::DEFAULT_FILE_NAME,
            $overrides,
            $this->createMock(Configuration::class),
            $sspBridgeMock,
            $this->createMock(ValueAbstracts::class),
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
     * Find a row by its label.
     *
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     */
    protected function findRowByLabel(array $sections, string $label): ?Row
    {
        foreach ($this->flattenRows($sections) as $row) {
            if ($row->getLabel() === $label) {
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
