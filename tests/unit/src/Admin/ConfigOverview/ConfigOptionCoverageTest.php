<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Guards the configuration overview screens against config drift.
 *
 * Every ModuleConfig::OPTION_* constant must either be displayed by one of the overview builders,
 * or be listed below together with the reason it is not. Adding a new config option therefore
 * forces a deliberate decision about whether administrators can see it, which is how these screens
 * fell behind in the first place.
 *
 * When this test fails for an option you just added:
 *  - add a Row for it in the builder for the screen it belongs to; or
 *  - if it must not be displayed at all (secrets, dead options), add it to the exclusion list below
 *    with a short reason.
 */
#[CoversNothing]
class ConfigOptionCoverageTest extends TestCase
{
    use OverviewTestTrait;
    use ProtocolOverviewTestTrait;
    use FederationOverviewTestTrait;

    /**
     * Constants which are intentionally not shown on any overview screen, and why.
     */
    protected const array NOT_DISPLAYED = [
        'OPTION_PKI_PRIVATE_KEY_PASSPHRASE' =>
            'Legacy option which is no longer read anywhere in the module.',

        'OPTION_CRON_TAG' =>
            'Operational (storage cleanup) setting. Belongs to a general settings screen, which does not exist yet.',
        'OPTION_ADMIN_UI_PERMISSIONS' =>
            'Admin UI setting. Belongs to a general settings screen, which does not exist yet.',
        'OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE' =>
            'Admin UI setting. Belongs to a general settings screen, which does not exist yet.',

        'OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED' =>
            'Verifiable Credential API endpoint, belongs to the verifiable credential screen.',
        'OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME' =>
            'Only used when building Verifiable Credential offers, belongs to the verifiable credential screen.',
        'OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP' =>
            'Only used when building Verifiable Credential offers, belongs to the verifiable credential screen.',
    ];

    /**
     * Constant name prefixes belonging to a screen which has not been reworked yet.
     */
    protected const array PENDING_SCREEN_PREFIXES = [
        'OPTION_VCI_' => 'Verifiable Credential option, belongs to the verifiable credential screen.',
    ];

    /**
     * @return array<string, string> Constant name to constant value.
     */
    protected function moduleConfigOptions(): array
    {
        $options = [];

        /** @var mixed $value */
        foreach ((new ReflectionClass(ModuleConfig::class))->getConstants() as $name => $value) {
            if (!str_starts_with($name, 'OPTION_') || !is_string($value)) {
                continue;
            }

            $options[$name] = $value;
        }

        return $options;
    }

    /**
     * Config option values displayed by a single builder, in the order the rows appear.
     *
     * @return string[]
     * @throws \Exception
     */
    protected function displayedBy(string $screen): array
    {
        $sections = match ($screen) {
            'protocol' => $this->buildProtocolOverviewBuilder()->build(),
            'federation' => $this->buildFederationOverviewBuilder()->build(),
            default => self::fail("Unknown screen '$screen'."),
        };

        $displayed = [];

        foreach ($this->flattenRows($sections) as $row) {
            if (is_null($configOption = $row->getConfigOption())) {
                continue;
            }

            $displayed[] = $configOption;
        }

        return $displayed;
    }

    /**
     * Config option values displayed anywhere in the admin UI.
     *
     * @return string[]
     * @throws \Exception
     */
    protected function displayedAnywhere(): array
    {
        return array_merge($this->displayedBy('protocol'), $this->displayedBy('federation'));
    }

    protected function isExcluded(string $constantName): bool
    {
        if (array_key_exists($constantName, self::NOT_DISPLAYED)) {
            return true;
        }

        foreach (array_keys(self::PENDING_SCREEN_PREFIXES) as $prefix) {
            if (str_starts_with($constantName, $prefix)) {
                return true;
            }
        }

        return false;
    }

    public function testFoundModuleConfigOptions(): void
    {
        // Sanity check, so that a broken reflection lookup can not make the coverage test pass.
        $this->assertGreaterThan(50, count($this->moduleConfigOptions()));
    }

    /**
     * @throws \Exception
     */
    public function testEveryConfigOptionIsDisplayedOrExplicitlyExcluded(): void
    {
        $displayed = $this->displayedAnywhere();
        $missing = [];

        foreach ($this->moduleConfigOptions() as $name => $value) {
            if (in_array($value, $displayed, true) || $this->isExcluded($name)) {
                continue;
            }

            $missing[] = $name;
        }

        $this->assertSame(
            [],
            $missing,
            'These ModuleConfig options are shown on no overview screen and are not listed as ' .
            'intentionally excluded: ' . implode(', ', $missing) . '. Add a Row for them in the ' .
            'relevant builder, or add them to this test\'s exclusion list with a reason.',
        );
    }

    /**
     * @throws \Exception
     */
    public function testExclusionListHasNoStaleEntries(): void
    {
        $options = $this->moduleConfigOptions();
        $displayed = $this->displayedAnywhere();

        foreach (array_keys(self::NOT_DISPLAYED) as $name) {
            $this->assertArrayHasKey(
                $name,
                $options,
                "Excluded option $name no longer exists in ModuleConfig, so remove it from the exclusion list.",
            );

            $this->assertNotContains(
                $options[$name],
                $displayed,
                "Excluded option $name is in fact displayed, so remove it from the exclusion list.",
            );
        }
    }

    /**
     * @throws \Exception
     */
    public function testScreensDisplayOnlyKnownConfigOptions(): void
    {
        $knownValues = array_values($this->moduleConfigOptions());

        foreach ($this->displayedAnywhere() as $configOption) {
            $this->assertContains(
                $configOption,
                $knownValues,
                "An overview screen references '$configOption', which is not a ModuleConfig option.",
            );
        }
    }

    /**
     * An option may legitimately appear on more than one screen (the issuer is both a protocol and
     * a federation concern), but showing it twice on the same screen is a mistake.
     *
     * @throws \Exception
     */
    public function testNoScreenShowsTheSameOptionTwice(): void
    {
        foreach (['protocol', 'federation'] as $screen) {
            $displayed = $this->displayedBy($screen);

            $this->assertSame(
                array_values(array_unique($displayed)),
                $displayed,
                "The $screen screen shows the same config option in more than one row.",
            );
        }
    }
}
