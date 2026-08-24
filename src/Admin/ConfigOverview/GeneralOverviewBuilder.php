<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\AuthContextService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use Throwable;

/**
 * Builds the sections shown on the general configuration overview screen.
 *
 * This screen is home to the options which belong to no single protocol: how the administration UI
 * behaves, and when storage is cleaned up. Options which are part of OpenID Connect, OpenID
 * Federation or Verifiable Credential Issuance belong on their own screens.
 *
 * As with the other screens, every row which corresponds to a ModuleConfig::OPTION_* constant records
 * it, so ConfigOptionCoverageTest can assert no option silently goes missing.
 *
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\AbstractOverviewBuilder
 */
class GeneralOverviewBuilder extends AbstractOverviewBuilder
{
    /**
     * Key inside the permissions option which names the attribute to inspect, rather than a
     * permission. AuthContextService reads it separately, so it must not be listed as a permission.
     */
    protected const string PERMISSIONS_ATTRIBUTE_KEY = 'attribute';

    /**
     * Permissions the module ever asks for. Any other key in the permissions option is never
     * consulted, so granting it has no effect.
     */
    protected const array RECOGNIZED_PERMISSIONS = [AuthContextService::PERM_CLIENT];

    /** The configured permission is not one the module ever checks. */
    protected const string REASON_NOT_CHECKED = 'notChecked';

    /** A permission the module does check, but with no entitlement a user could present. */
    protected const string REASON_NO_ENTITLEMENTS = 'noEntitlements';

    /**
     * SimpleSAMLphp module which dispatches the cron hooks. Without it the configured tag is never
     * run, no matter what it is set to.
     */
    protected const string CRON_MODULE_NAME = 'cron';

    /** Configuration file of the cron module, which lists the tags it may run. */
    protected const string CRON_CONFIG_FILE_NAME = 'module_cron.php';

    /** Option in the cron module configuration holding the tags it may run. */
    protected const string CRON_ALLOWED_TAGS_OPTION = 'allowed_tags';

    /**
     * Bounds and fallback ClientRepository reads the pagination size with. Repeated here so the
     * screen resolves the value exactly as the client registry does.
     */
    protected const int MIN_ITEMS_PER_PAGE = 1;

    protected const int MAX_ITEMS_PER_PAGE = 100;

    protected const int DEFAULT_ITEMS_PER_PAGE = 20;


    public function __construct(
        ModuleConfig $moduleConfig,
        Routes $routes,
        DateIntervalFormatter $dateIntervalFormatter,
        LoggerService $logger,
        protected readonly SspBridge $sspBridge,
    ) {
        parent::__construct($moduleConfig, $routes, $dateIntervalFormatter, $logger);
    }


    /**
     * @return \SimpleSAML\Module\oidc\Admin\ConfigOverview\Section[]
     */
    public function build(): array
    {
        return [
            $this->buildAdministrationUiSection(),
            $this->buildStorageCleanupSection(),
        ];
    }


    protected function buildAdministrationUiSection(): Section
    {
        return new Section(
            Translate::noop('Administration UI'),
            'administration-ui',
            $this->buildPermissionsRow(),
            $this->buildItemsPerPageRow(),
        );
    }


    protected function buildStorageCleanupSection(): Section
    {
        return new Section(
            Translate::noop('Storage Cleanup'),
            'storage-cleanup',
            $this->buildCronTagRow(),
        );
    }


    /**
     * Row describing who, besides a SimpleSAMLphp administrator, may use the client registry.
     */
    protected function buildPermissionsRow(): Row
    {
        return $this->guardRow(
            Translate::noop('Permissions'),
            ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS,
            function (): Row {
                // Read like AuthContextService does, which takes the option as a config item and so
                // rejects anything which is not an array.
                $permissions = $this->moduleConfig->config()
                    ->getOptionalArray(ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS, null) ?? [];

                /** @var mixed $attribute */
                $attribute = $permissions[self::PERMISSIONS_ATTRIBUTE_KEY] ?? null;

                return new Row(
                    Translate::noop('Permissions'),
                    [
                        // Only a string is usable: requirePermission() reads the attribute name
                        // through getString(), which rejects every other type.
                        'attribute' => is_string($attribute) ? $attribute : null,
                        'isAttributeInvalid' => !is_null($attribute) && !is_string($attribute),
                        'permissions' => $this->buildPermissionList($permissions),
                    ],
                    ConfigOverviewValueTypeEnum::AdminUiPermissions,
                    ModuleConfig::OPTION_ADMIN_UI_PERMISSIONS,
                    is_string($attribute) ? Translate::noop(
                        'Checked when someone who is not a SimpleSAMLphp administrator opens the ' .
                        'client registry. Such a user only ever sees the clients they own.',
                    ) : Translate::noop(
                        'No attribute to inspect is configured, so permissions are off and only a ' .
                        'SimpleSAMLphp administrator can use the client registry.',
                    ),
                );
            },
        );
    }


    /**
     * Describe every configured permission, and whether it can grant anything.
     *
     * @param array<array-key,mixed> $permissions The permissions option, as configured.
     * @return list<array{name: string, entitlements: string[], ineffectiveReason: ?string}>
     */
    protected function buildPermissionList(array $permissions): array
    {
        $list = [];

        /** @var mixed $value */
        foreach ($permissions as $key => $value) {
            // Array keys can be integers, while a permission is always requested by name.
            $name = (string)$key;

            if ($name === self::PERMISSIONS_ATTRIBUTE_KEY) {
                continue;
            }

            $entitlements = $this->resolveEntitlements($value);

            $list[] = [
                'name' => $name,
                'entitlements' => $entitlements,
                'ineffectiveReason' => match (true) {
                    !in_array($name, self::RECOGNIZED_PERMISSIONS, true) => self::REASON_NOT_CHECKED,
                    $entitlements === [] => self::REASON_NO_ENTITLEMENTS,
                    default => null,
                },
            ];
        }

        return $list;
    }


    /**
     * Entitlements a user could present to be granted a permission.
     *
     * requirePermission() reads them through getArrayizeString(), which wraps a lone string into an
     * array but rejects a list holding anything other than strings. Such a value is reported as no
     * entitlements at all, since the check it takes part in can only fail.
     *
     * @return string[]
     */
    protected function resolveEntitlements(mixed $value): array
    {
        $entitlements = is_array($value) ? array_values($value) : [$value];

        foreach ($entitlements as $entitlement) {
            if (!is_string($entitlement)) {
                return [];
            }
        }

        /** @var string[] $entitlements */
        return $entitlements;
    }


    protected function buildItemsPerPageRow(): Row
    {
        return $this->guardRow(
            Translate::noop('Items Per Page'),
            ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
            function (): Row {
                $isConfigured = $this->moduleConfig->config()
                    ->hasValue(ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE);

                // Resolved exactly like ClientRepository does, so a value outside the allowed range
                // fails here too, instead of only when the client registry is opened.
                $itemsPerPage = $this->moduleConfig->config()->getOptionalIntegerRange(
                    ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
                    self::MIN_ITEMS_PER_PAGE,
                    self::MAX_ITEMS_PER_PAGE,
                    self::DEFAULT_ITEMS_PER_PAGE,
                );

                return new Row(
                    Translate::noop('Items Per Page'),
                    (string)$itemsPerPage,
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_ADMIN_UI_PAGINATION_ITEMS_PER_PAGE,
                    $isConfigured ?
                    Translate::noop('Number of entries listed per page in the client registry.') :
                    Translate::noop(
                        'Number of entries listed per page in the client registry. Not set, so the ' .
                        'default shown here is used.',
                    ),
                );
            },
        );
    }


    protected function buildCronTagRow(): Row
    {
        return $this->guardRow(
            Translate::noop('Cron Tag'),
            ModuleConfig::OPTION_CRON_TAG,
            function (): Row {
                // Read untyped, like the cron hook does. It compares the configured value with the
                // tag being run, so a value which is not a usable tag never matches rather than
                // failing, and the effect is simply that cleanup never happens.
                /** @var mixed $cronTag */
                $cronTag = $this->moduleConfig->config()
                    ->getOptionalValue(ModuleConfig::OPTION_CRON_TAG, null);

                if (!is_string($cronTag) || $cronTag === '') {
                    return new Row(
                        Translate::noop('Cron Tag'),
                        // A placeholder rather than configured data, so it is UI text.
                        Translate::noop('N/A'),
                        ConfigOverviewValueTypeEnum::Text,
                        ModuleConfig::OPTION_CRON_TAG,
                        null,
                        Translate::noop(
                            'No usable cron tag is set, so expired and invalid entries are never ' .
                            'removed from storage and the module tables keep growing.',
                        ),
                    );
                }

                return new Row(
                    Translate::noop('Cron Tag'),
                    $cronTag,
                    ConfigOverviewValueTypeEnum::RawText,
                    ModuleConfig::OPTION_CRON_TAG,
                    Translate::noop(
                        'Expired and invalid entries are removed from storage whenever the ' .
                        'SimpleSAMLphp cron module runs this tag.',
                    ),
                    $this->describeUndispatchableCronTag($cronTag),
                );
            },
        );
    }


    /**
     * Warning for a cron tag which can never reach this module, or null when it can.
     *
     * The tag is only ever handed to the module's cron hook by the SimpleSAMLphp cron module, which
     * both has to be enabled and has to be allowed to run that particular tag. Neither is visible
     * from this module's own configuration, so an otherwise sound looking tag can be inert.
     */
    protected function describeUndispatchableCronTag(string $cronTag): ?string
    {
        try {
            $isCronModuleEnabled = $this->sspBridge->module()->isModuleEnabled(self::CRON_MODULE_NAME);
        } catch (Throwable $exception) {
            $this->reportUnreadableCronState($exception);

            // Whether the module is enabled could not be established, so no claim is made.
            return null;
        }

        if (!$isCronModuleEnabled) {
            return Translate::noop(
                'The SimpleSAMLphp cron module is not enabled, so this tag is never run and ' .
                'expired and invalid entries are never removed from storage.',
            );
        }

        try {
            $allowedTags = $this->sspBridge->module()
                ->getOptionalConfig(self::CRON_CONFIG_FILE_NAME)
                ->getOptionalArray(self::CRON_ALLOWED_TAGS_OPTION, null);
        } catch (Throwable $exception) {
            $this->reportUnreadableCronState($exception);

            // The option holds something which is not an array, which is what Cron::isValidTag()
            // hands to getArray() before any hook is called.
            return $this->describeUnusableCronTagList();
        }

        // isValidTag() reads the option through getValue(), which treats an absent or null value as
        // a missing required option rather than as 'every tag is allowed'. Its 'return true' branch
        // is therefore unreachable, and such a configuration lets no tag through at all.
        if (is_null($allowedTags)) {
            return $this->describeUnusableCronTagList();
        }

        if (!in_array($cronTag, $allowedTags, true)) {
            return Translate::noop(
                'This tag is not one the SimpleSAMLphp cron module is allowed to run, so it ' .
                'is never run and expired and invalid entries are never removed from storage.',
            );
        }

        return null;
    }


    /**
     * The cron module has no usable list of tags it may run, so it refuses every one of them.
     */
    protected function describeUnusableCronTagList(): string
    {
        return Translate::noop(
            'The SimpleSAMLphp cron module has no usable list of the tags it may run, so it ' .
            'refuses every tag, and expired and invalid entries are never removed from storage.',
        );
    }


    protected function reportUnreadableCronState(Throwable $exception): void
    {
        $this->logger->warning(
            'Configuration overview could not read the cron module state: ' . $exception->getMessage(),
            ['exceptionClass' => $exception::class],
        );
    }
}
