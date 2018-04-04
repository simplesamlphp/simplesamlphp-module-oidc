<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use SimpleSAML\Module;
use SimpleSAML\Utils\HTTP;

class ConfigurationService
{
    public function getSimpleSAMLConfiguration(): \SimpleSAML_Configuration
    {
        return \SimpleSAML_Configuration::getInstance();
    }

    public function getOpenIDConnectConfiguration(): \SimpleSAML_Configuration
    {
        return \SimpleSAML_Configuration::getConfig('module_oidc.php');
    }

    public function getSimpleSAMLSelfURLHost()
    {
        return HTTP::getSelfURLHost();
    }

    public function getOpenIdConnectModuleURL(string $path = null): string
    {
        $base = Module::getModuleURL('oidc');

        if ($path) {
            $base .= "/{$path}";
        }

        return $base;
    }
}
