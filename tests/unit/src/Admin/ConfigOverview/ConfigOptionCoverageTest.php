<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SimpleSAML\Module\oidc\ModuleConfig;

/**
 * Guards the protocol settings screen against configuration drift.
 *
 * Every ModuleConfig::OPTION_* constant must either be displayed by ProtocolOverviewBuilder, or be
 * listed below together with the reason it is not. Adding a new config option therefore forces a
 * deliberate decision about whether administrators can see it, which is how the screen fell behind
 * in the first place.
 *
 * When this test fails for an option you just added:
 *  - if it is a protocol option, add a Row for it in ProtocolOverviewBuilder;
 *  - if it belongs to another screen (federation, verifiable credential) or must not be displayed
 *    at all (secrets), add it to the exclusion list below with a short reason.
 */
#[CoversNothing]
class ConfigOptionCoverageTest extends TestCase
{
    use ProtocolOverviewTestTrait;

    /**
     * Constants which are intentionally not shown on the protocol settings screen, and why.
     */
    protected const array NOT_ON_PROTOCOL_SCREEN = [
        'OPTION_PKI_PRIVATE_KEY_PASSPHRASE' =>
            'Legacy option which is no longer read anywhere in the module.',

        'OPTION_CRON_TAG' =>
            'Operational (storage cleanup) setting, not a protocol one. Belongs to a general settings screen.',
        'OPTION_ADMIN_UI_PERMISSIONS' =>
            'Admin UI setting, not a protocol one. Belongs to a general settings screen.',
        'OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE' =>
            'Admin UI setting, not a protocol one. Belongs to a general settings screen.',

        'OPTION_ORGANIZATION_NAME' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_DISPLAY_NAME' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_DESCRIPTION' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_KEYWORDS' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_CONTACTS' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_LOGO_URI' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_POLICY_URI' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_INFORMATION_URI' => 'Common federation entity parameter, shown on the federation screen.',
        'OPTION_ORGANIZATION_URI' => 'Common federation entity parameter, shown on the federation screen.',

        'OPTION_API_VCI_CREDENTIAL_OFFER_ENDPOINT_ENABLED' =>
            'Verifiable Credential API endpoint, shown on the verifiable credential screen.',
        'OPTION_DEFAULT_USERS_EMAIL_ATTRIBUTE_NAME' =>
            'Only used when building Verifiable Credential offers, shown on the verifiable credential screen.',
        'OPTION_AUTH_SOURCES_TO_USERS_EMAIL_ATTRIBUTE_NAME_MAP' =>
            'Only used when building Verifiable Credential offers, shown on the verifiable credential screen.',
    ];

    /**
     * Constant name prefixes belonging to other configuration screens.
     */
    protected const array OTHER_SCREEN_PREFIXES = [
        'OPTION_FEDERATION_' => 'OpenID Federation option, shown on the federation screen.',
        'OPTION_VCI_' => 'Verifiable Credential option, shown on the verifiable credential screen.',
    ];

    /**
     * Options which match one of the prefixes above but must nevertheless appear on the protocol
     * screen, because that is where the behaviour they control is configured. Without this, the
     * blanket prefix rule would quietly mark them as somebody else's problem.
     */
    protected const array PREFIX_EXCEPTIONS = [
        'OPTION_FEDERATION_REQUEST_URI_ALLOWED_PREFIXES' =>
            'The SSRF allowlist for fetching a Request Object by reference, which belongs next to ' .
            'the other request_uri settings on the protocol screen.',
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
     * @return string[] Config option values displayed on the protocol screen.
     * @throws \Exception
     */
    protected function displayedConfigOptions(): array
    {
        $displayed = [];

        foreach ($this->flattenRows($this->buildProtocolOverviewBuilder()->build()) as $row) {
            if (is_null($configOption = $row->getConfigOption())) {
                continue;
            }

            $displayed[] = $configOption;
        }

        return $displayed;
    }

    protected function isExcluded(string $constantName): bool
    {
        if (array_key_exists($constantName, self::PREFIX_EXCEPTIONS)) {
            return false;
        }

        if (array_key_exists($constantName, self::NOT_ON_PROTOCOL_SCREEN)) {
            return true;
        }

        foreach (array_keys(self::OTHER_SCREEN_PREFIXES) as $prefix) {
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
        $displayed = $this->displayedConfigOptions();
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
            'These ModuleConfig options are neither shown on the protocol settings screen nor listed as ' .
            'intentionally excluded: ' . implode(', ', $missing) . '. Add a Row for them in ' .
            'ProtocolOverviewBuilder, or add them to this test\'s exclusion list with a reason.',
        );
    }

    /**
     * @throws \Exception
     */
    public function testExclusionListHasNoStaleEntries(): void
    {
        $options = $this->moduleConfigOptions();
        $displayed = $this->displayedConfigOptions();

        foreach (array_keys(self::NOT_ON_PROTOCOL_SCREEN) as $name) {
            $this->assertArrayHasKey(
                $name,
                $options,
                "Excluded option $name no longer exists in ModuleConfig, so remove it from the exclusion list.",
            );

            $this->assertNotContains(
                $options[$name],
                $displayed,
                "Excluded option $name is in fact displayed on the protocol settings screen, so remove it " .
                'from the exclusion list.',
            );
        }
    }

    /**
     * @throws \Exception
     */
    public function testPrefixExceptionsAreActuallyDisplayed(): void
    {
        $options = $this->moduleConfigOptions();
        $displayed = $this->displayedConfigOptions();

        foreach (array_keys(self::PREFIX_EXCEPTIONS) as $name) {
            $this->assertArrayHasKey(
                $name,
                $options,
                "Prefix exception $name no longer exists in ModuleConfig, so remove it from the list.",
            );

            $this->assertContains(
                $options[$name],
                $displayed,
                "$name is listed as an exception to the other-screen prefix rules, so it must be shown " .
                'on the protocol settings screen. Add a Row for it in ProtocolOverviewBuilder, or drop ' .
                'the exception.',
            );
        }
    }

    /**
     * @throws \Exception
     */
    public function testProtocolScreenDisplaysOnlyKnownConfigOptions(): void
    {
        $knownValues = array_values($this->moduleConfigOptions());

        foreach ($this->displayedConfigOptions() as $configOption) {
            $this->assertContains(
                $configOption,
                $knownValues,
                "The protocol settings screen references '$configOption', which is not a ModuleConfig option.",
            );
        }
    }
}
