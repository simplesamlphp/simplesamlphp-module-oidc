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
            'url' => $moduleConfig->getModuleUrl(RoutesEnum::AdminConfigOverview->value),
            'name' => Translate::noop('OIDC'),
        ],
    ];

    // Put our entry before the "Log out" entry.
    array_splice($template->data[$menuKey], -1, 0, $oidcMenuEntry);

    $template->getLocalization()->addModuleDomain(ModuleConfig::MODULE_NAME);
}
