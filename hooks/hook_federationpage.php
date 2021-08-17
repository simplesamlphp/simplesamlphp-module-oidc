<?php

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

use SimpleSAML\XHTML\Template;
use SimpleSAML\Locale\Translate;

/**
 * @param Template &$template
 *
 * @return void
 */
function oidc_hook_federationpage(Template &$template)
{
    $href = \SimpleSAML\Module::getModuleURL('oidc/clients/index.php');
    $text = Translate::noop('OpenID Connect Registry');

    if (! (new \SimpleSAML\Module\oidc\Services\DatabaseMigration())->isUpdated()) {
        $href = \SimpleSAML\Module::getModuleURL('oidc/install.php');
        $text = Translate::noop('OpenID Connect Installation');
    }

    $template->data['links'][] = [
        'href' => $href,
        'text' => $text,
    ];
}
