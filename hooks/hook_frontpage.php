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

function oidc_hook_frontpage(array &$links): void
{
    if (!is_array($links['federation'])) {
        $links['federation'] = [];
    }

    $isUpdated = (new DatabaseMigration())->isUpdated();

    if (!$isUpdated) {
        $links['federation']['oidcregistry'] = [
            'href' => Module::getModuleURL('oidc/install.php'),
            'text' => [
                'en' => 'OpenID Connect Installation',
                'es' => 'Instalación de OpenID Connect',
                'it' => 'Installazione di OpenID Connect',
            ],
            'shorttext' => [
                'en' => 'OpenID Connect Installation',
                'es' => 'Instalación de OpenID Connect',
                'it' => 'Installazione di OpenID Connect',
            ],
        ];

        return;
    }

    $links['federation']['oidcregistry'] = [
        'href' => Module::getModuleURL('oidc/admin-clients/index.php'),
        'text' => [
            'en' => 'OpenID Connect Client Registry',
            'es' => 'Registro de clientes OpenID Connect',
            'it' => 'Registro dei clients OpenID Connect',
        ],
        'shorttext' => [
            'en' => 'OpenID Connect Registry',
            'es' => 'Registro OpenID Connect',
            'it' => 'Registro dei clients OpenID Connect',
        ],
    ];
}
