<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use SimpleSAML\Module;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Locale\Translate;

function oidc_hook_federationpage(Template $template): void
{
    $href = Module::getModuleURL('oidc/admin-clients/index.php');
    $text = Translate::noop('OpenID Connect Registry');

    if (! (new DatabaseMigration())->isUpdated()) {
        $href = Module::getModuleURL('oidc/install.php');
        $text = Translate::noop('OpenID Connect Installation');
    }

    if (!is_array($template->data['links'])) {
        $template->data['links'] = [];
    }

    $template->data['links'][] = [
        'href' => $href,
        'text' => $text,
    ];
}
