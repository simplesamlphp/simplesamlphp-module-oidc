<?php

declare(strict_types=1);

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\XHTML\Template;

/**
 * @param \SimpleSAML\XHTML\Template $template
 */
function oidc_hook_federationpage(Template $template): void
{
    $routes = new Module\oidc\Utils\Routes(
        new ModuleConfig(),
        new Module\oidc\Bridges\SspBridge(),
    );

    $href = $routes->urlAdminClients();
    $text = Translate::noop('OIDC Client Registry');

    if (! (new DatabaseMigration())->isMigrated()) {
        $href = $routes->urlAdminMigrations();
        $text = Translate::noop('OIDC Installation');
    }

    if (!is_array($template->data['links'])) {
        $template->data['links'] = [];
    }

    $template->data['links'][] = [
        'href' => $href,
        'text' => $text,
    ];
}
