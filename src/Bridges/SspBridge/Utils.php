<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;

class Utils
{
    protected static ?Config $config = null;
    protected static ?HTTP $http = null;

    public function config(): Config
    {
        return self::$config ??= new Config();
    }

    public function http(): HTTP
    {
        return self::$http ??= new HTTP();
    }
}
