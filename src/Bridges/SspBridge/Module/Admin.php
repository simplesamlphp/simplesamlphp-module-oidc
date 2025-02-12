<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge\Module;

use SimpleSAML\Module\admin\Controller\Menu;

class Admin
{
    public function buildSspAdminMenu(): Menu
    {
        return new Menu();
    }
}
