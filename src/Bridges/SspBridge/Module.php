<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Module as SspModule;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module\Admin;

class Module
{
    protected static ?SspModule\oidc\Bridges\SspBridge\Module\Admin $admin = null;

    public function admin(): Admin
    {
        return self::$admin ??= new Admin();
    }

    public function getModuleUrl(string $resource, array $parameters = []): string
    {
        return SspModule::getModuleURL($resource, $parameters);
    }

    /**
     * @throws \Exception
     */
    public function isModuleEnabled(string $moduleName): bool
    {
        return SspModule::isModuleEnabled($moduleName);
    }
}
