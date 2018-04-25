<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

function oidc_hook_frontpage(&$links)
{
    assert('is_array($links)');
    assert('array_key_exists("links", $links)');

    $isUpdated = (new \SimpleSAML\Modules\OpenIDConnect\Services\DatabaseMigration())->isUpdated();

    if (!$isUpdated) {
        $links['federation']['oidcregistry'] = [
            'href' => \SimpleSAML_Module::getModuleURL('oidc/install.php'),
            'text' => [
                'en' => 'OpenID Connect Installation',
                'es' => 'Instalación de OpenID Connect',
            ],
            'shorttext' => [
                'en' => 'OpenID Connect Installation',
                'es' => 'Instalación de OpenID Connect',
            ],
        ];

        return;
    }

    $links['federation']['oidcregistry'] = [
        'href' => \SimpleSAML_Module::getModuleURL('oidc/clients/'),
        'text' => [
            'en' => 'OpenID Connect Client Registry',
            'es' => 'Registro de clientes OpenID Connect',
        ],
        'shorttext' => [
            'en' => 'OpenID Connect Registry',
            'es' => 'Registro OpenID Connect',
        ],
    ];
}
