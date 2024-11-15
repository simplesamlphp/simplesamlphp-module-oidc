<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\XHTML\Template;

/** @noinspection PhpParameterByRefIsNotUsedAsReferenceInspection Reference is actually used by SimpleSAMLphp */
function oidc_hook_adminmenu(Template &$template): void
{
    $menuKey = 'menu';

    if (!isset($template->data[$menuKey]) || !is_array($template->data[$menuKey])) {
        return;
    }

    $moduleConfig = new ModuleConfig();

    $oidcMenuEntry = [
        ModuleConfig::MODULE_NAME => [
            'url' => $moduleConfig->getModuleUrl(RoutesEnum::AdminConfigProtocol->value),
            'name' => Translate::noop('OIDC'),
        ],
    ];

    // Put OIDC entry before the 'Log out' entry, if it exists.
    $logoutEntryKey = 'logout';
    $logoutEntryValue = null;
    if (
        array_key_exists($logoutEntryKey, $template->data[$menuKey]) &&
        is_array($template->data[$menuKey][$logoutEntryKey])
    ) {
        $logoutEntryValue = $template->data[$menuKey][$logoutEntryKey];
        unset($template->data[$menuKey][$logoutEntryKey]);
    }

    $template->data[$menuKey] += $oidcMenuEntry;

    if ($logoutEntryValue !== null) {
        $template->data[$menuKey][$logoutEntryKey] = $logoutEntryValue;
    }

    $template->getLocalization()->addModuleDomain(ModuleConfig::MODULE_NAME);
}
