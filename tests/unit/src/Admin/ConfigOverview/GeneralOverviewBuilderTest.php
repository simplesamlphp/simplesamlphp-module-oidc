<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\GeneralOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\Section;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;

#[CoversClass(GeneralOverviewBuilder::class)]
#[CoversClass(AbstractOverviewBuilder::class)]
#[AllowMockObjectsWithoutExpectations]
class GeneralOverviewBuilderTest extends TestCase
{
    use OverviewTestTrait;
    use GeneralOverviewTestTrait;


    /**
     * The prepared permissions value of the given sections.
     *
     * @param \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[] $sections
     */
    protected function permissionsValue(array $sections): array
    {
        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS);
        $this->assertNotNull($row);
        $this->assertSame(ConfigOverviewValueTypeEnum::AdminUiPermissions, $row->getValueType());

        $value = $row->getValue();
        $this->assertIsArray($value);

        return $value;
    }


    /**
     * A single prepared permission entry, by name.
     */
    protected function permissionEntry(array $sections, string $name): array
    {
        /** @var array<array{name: string}> $permissions */
        $permissions = $this->permissionsValue($sections)['permissions'];

        foreach ($permissions as $permission) {
            if ($permission['name'] === $name) {
                return $permission;
            }
        }

        $this->fail("No permission entry named '$name' was prepared.");
    }


    /**
     * @throws \Exception
     */
    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(GeneralOverviewBuilder::class, $this->buildGeneralOverviewBuilder());
    }


    /**
     * @throws \Exception
     */
    public function testCanBuildSections(): void
    {
        $sections = $this->buildGeneralOverviewBuilder()->build();

        $this->assertNotEmpty($sections);

        foreach ($sections as $section) {
            $this->assertInstanceOf(Section::class, $section);
            $this->assertNotEmpty($section->getTitle());
            $this->assertNotEmpty($section->getAnchor());
            $this->assertNotEmpty($section->getRows());
        }
    }


    /**
     * @throws \Exception
     */
    public function testSectionAnchorsAreUnique(): void
    {
        $anchors = array_map(
            fn(Section $section): string => $section->getAnchor(),
            $this->buildGeneralOverviewBuilder()->build(),
        );

        $this->assertSame($anchors, array_unique($anchors));
    }


    /**
     * @throws \Exception
     */
    public function testEveryRowHasALabel(): void
    {
        foreach ($this->flattenRows($this->buildGeneralOverviewBuilder()->build()) as $row) {
            $this->assertNotEmpty($row->getLabel());
        }
    }


    /**
     * @throws \Exception
     */
    public function testShowsConfiguredCronTag(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder([ModuleConfig::OPTION_CRON_TAG => 'daily'])->build(),
            ModuleConfig::OPTION_CRON_TAG,
        );

        $this->assertNotNull($row);
        $this->assertSame('daily', $row->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::RawText, $row->getValueType());
        $this->assertNull($row->getWarning());
        $this->assertStringContainsString('cron module runs this tag', (string)$row->getNote());
    }


    /**
     * Without a tag the cron hook returns before cleaning anything, so the tables grow unbounded.
     *
     * @throws \Exception
     */
    public function testWarnsWhenCronTagIsNotSet(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder([ModuleConfig::OPTION_CRON_TAG => null])->build(),
            ModuleConfig::OPTION_CRON_TAG,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertSame(ConfigOverviewValueTypeEnum::Text, $row->getValueType());
        $this->assertStringContainsString('never', (string)$row->getWarning());
    }


    /**
     * The hook compares the configured value with the tag being run, so a value which is not a
     * usable tag never matches. That must be reported as cleanup not running, and not as the option
     * failing to resolve.
     *
     * @throws \Exception
     */
    public function testWarnsWhenCronTagCanNotMatchATag(): void
    {
        foreach ([123, '', ['hourly']] as $cronTag) {
            $row = $this->findRowForOption(
                $this->buildGeneralOverviewBuilder([ModuleConfig::OPTION_CRON_TAG => $cronTag])->build(),
                ModuleConfig::OPTION_CRON_TAG,
            );

            $this->assertNotNull($row);
            $this->assertSame('N/A', $row->getValue());
            $this->assertStringContainsString('No usable cron tag', (string)$row->getWarning());
        }
    }


    /**
     * A tag only ever reaches the module through the cron module's hook dispatch.
     *
     * @throws \Exception
     */
    public function testWarnsWhenCronModuleIsNotEnabled(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_CRON_TAG => 'hourly'],
                isCronModuleEnabled: false,
            )->build(),
            ModuleConfig::OPTION_CRON_TAG,
        );

        $this->assertNotNull($row);
        $this->assertSame('hourly', $row->getValue());
        $this->assertStringContainsString('cron module is not enabled', (string)$row->getWarning());
    }


    /**
     * Cron::runTag() refuses a tag which is not allowed, so the hook is never reached. Nothing in
     * this module's own configuration hints at that, which is exactly why the screen must say so.
     *
     * @throws \Exception
     */
    public function testWarnsWhenCronModuleMayNotRunTheTag(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_CRON_TAG => 'oidc-cleanup'],
                allowedCronTags: ['daily', 'hourly', 'frequent'],
            )->build(),
            ModuleConfig::OPTION_CRON_TAG,
        );

        $this->assertNotNull($row);
        $this->assertSame('oidc-cleanup', $row->getValue());
        $this->assertStringContainsString(
            'not one the SimpleSAMLphp cron module is allowed',
            (string)$row->getWarning(),
        );
    }


    /**
     * Cron::isValidTag() reads the allowed tags as a required option, so an absent one is not read
     * as 'anything goes': it makes the cron module throw for every tag, this module's included.
     * The same holds for a value it can not treat as a list.
     *
     * @throws \Exception
     */
    public function testWarnsWhenCronHasNoUsableTagList(): void
    {
        // A missing module_cron.php reaches this the same way, as an empty configuration.
        foreach ([null, 'hourly'] as $allowedCronTags) {
            $row = $this->findRowForOption(
                $this->buildGeneralOverviewBuilder(
                    [ModuleConfig::OPTION_CRON_TAG => 'hourly'],
                    allowedCronTags: $allowedCronTags,
                )->build(),
                ModuleConfig::OPTION_CRON_TAG,
            );

            $this->assertNotNull($row);
            $this->assertSame('hourly', $row->getValue());
            $this->assertStringContainsString('no usable list', (string)$row->getWarning());
        }
    }


    /**
     * @throws \Exception
     */
    public function testShowsItemsPerPage(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE => 42],
            )->build(),
            ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
        );

        $this->assertNotNull($row);
        $this->assertSame('42', $row->getValue());
        $this->assertStringNotContainsString('Not set', (string)$row->getNote());
    }


    /**
     * @throws \Exception
     */
    public function testShowsDefaultItemsPerPageWhenNotConfigured(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE => null],
            )->build(),
            ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
        );

        $this->assertNotNull($row);
        $this->assertSame('20', $row->getValue());
        $this->assertStringContainsString('Not set', (string)$row->getNote());
    }


    /**
     * ClientRepository resolves the value the same way, so an out of range value breaks the client
     * registry. The row must report that rather than show a number which is never used.
     *
     * @throws \Exception
     */
    public function testWarnsWhenItemsPerPageIsOutOfRange(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE => 101],
            )->build(),
            ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertStringContainsString('could not be resolved', (string)$row->getWarning());
    }


    /**
     * @throws \Exception
     */
    public function testShowsPermissions(): void
    {
        $sections = $this->buildGeneralOverviewBuilder([
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                'attribute' => 'eduPersonEntitlement',
                'client' => ['urn:example:oidc:manage:client'],
            ],
        ])->build();

        $value = $this->permissionsValue($sections);

        $this->assertSame('eduPersonEntitlement', $value['attribute']);
        $this->assertFalse($value['isAttributeInvalid']);

        $client = $this->permissionEntry($sections, 'client');
        $this->assertSame(['urn:example:oidc:manage:client'], $client['entitlements']);
        $this->assertNull($client['ineffectiveReason']);
    }


    /**
     * The entitlements are read through getArrayizeString(), which accepts a lone string too.
     *
     * @throws \Exception
     */
    public function testAcceptsASingleEntitlementString(): void
    {
        $sections = $this->buildGeneralOverviewBuilder([
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                'attribute' => 'eduPersonEntitlement',
                'client' => 'urn:example:oidc:manage:client',
            ],
        ])->build();

        $client = $this->permissionEntry($sections, 'client');

        $this->assertSame(['urn:example:oidc:manage:client'], $client['entitlements']);
        $this->assertNull($client['ineffectiveReason']);
    }


    /**
     * Without an attribute to inspect, requirePermission() reports permissions as not enabled and
     * every check falls back to administrator authentication.
     *
     * @throws \Exception
     */
    public function testReportsPermissionsAsNotEnabledWithoutAnAttribute(): void
    {
        $sections = $this->buildGeneralOverviewBuilder([
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                'client' => ['urn:example:oidc:manage:client'],
            ],
        ])->build();

        $value = $this->permissionsValue($sections);

        $this->assertNull($value['attribute']);
        $this->assertFalse($value['isAttributeInvalid']);

        // The configured permission is still listed, so it is not silently hidden.
        $this->assertSame(
            ['urn:example:oidc:manage:client'],
            $this->permissionEntry($sections, 'client')['entitlements'],
        );

        $row = $this->findRowForOption($sections, ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS);
        $this->assertNotNull($row);
        $this->assertStringContainsString('permissions are off', (string)$row->getNote());
    }


    /**
     * @throws \Exception
     */
    public function testReportsPermissionsAsNotEnabledWhenNotConfigured(): void
    {
        $value = $this->permissionsValue(
            $this->buildGeneralOverviewBuilder([ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => null])->build(),
        );

        $this->assertNull($value['attribute']);
        $this->assertSame([], $value['permissions']);
    }


    /**
     * getString() rejects a non-string attribute, which leaves the check failing for everyone.
     *
     * @throws \Exception
     */
    public function testMarksNonStringAttributeAsInvalid(): void
    {
        $value = $this->permissionsValue(
            $this->buildGeneralOverviewBuilder([
                ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                    'attribute' => ['eduPersonEntitlement'],
                    'client' => ['urn:example:oidc:manage:client'],
                ],
            ])->build(),
        );

        $this->assertNull($value['attribute']);
        $this->assertTrue($value['isAttributeInvalid']);
    }


    /**
     * Only the 'client' permission is ever requested, so any other key grants nothing.
     *
     * @throws \Exception
     */
    public function testMarksUnrecognizedPermissionAsNotChecked(): void
    {
        $sections = $this->buildGeneralOverviewBuilder([
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                'attribute' => 'eduPersonEntitlement',
                'client' => ['urn:example:oidc:manage:client'],
                'federation' => ['urn:example:oidc:manage:federation'],
            ],
        ])->build();

        $this->assertSame('notChecked', $this->permissionEntry($sections, 'federation')['ineffectiveReason']);
        $this->assertNull($this->permissionEntry($sections, 'client')['ineffectiveReason']);
    }


    /**
     * A permission nobody can present an entitlement for can only ever fall back to administrator
     * authentication, so listing it without a marker would overstate what it grants.
     *
     * @throws \Exception
     */
    public function testMarksPermissionWithoutUsableEntitlements(): void
    {
        // Empty, unset, holding a non-string, and holding a nested array: none of these can ever
        // match an entitlement the user presents.
        foreach ([[], null, [123], [['nested']]] as $entitlements) {
            $sections = $this->buildGeneralOverviewBuilder([
                ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                    'attribute' => 'eduPersonEntitlement',
                    'client' => $entitlements,
                ],
            ])->build();

            $client = $this->permissionEntry($sections, 'client');

            $this->assertSame([], $client['entitlements']);
            $this->assertSame('noEntitlements', $client['ineffectiveReason']);
        }
    }


    /**
     * The attribute names the option to read, so it must not be listed as a permission of its own.
     *
     * @throws \Exception
     */
    public function testDoesNotListTheAttributeKeyAsAPermission(): void
    {
        /** @var array<array{name: string}> $permissions */
        $permissions = $this->permissionsValue(
            $this->buildGeneralOverviewBuilder([
                ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => [
                    'attribute' => 'eduPersonEntitlement',
                    'client' => ['urn:example:oidc:manage:client'],
                ],
            ])->build(),
        )['permissions'];

        $this->assertSame(['client'], array_column($permissions, 'name'));
    }


    /**
     * A malformed option must fail on its own row rather than take the screen down.
     *
     * @throws \Exception
     */
    public function testSurvivesMalformedPermissions(): void
    {
        $row = $this->findRowForOption(
            $this->buildGeneralOverviewBuilder(
                [ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS => 'not-an-array'],
            )->build(),
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS,
        );

        $this->assertNotNull($row);
        $this->assertSame('N/A', $row->getValue());
        $this->assertStringContainsString('could not be resolved', (string)$row->getWarning());
    }
}
