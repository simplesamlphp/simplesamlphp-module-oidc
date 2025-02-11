<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Utils\Attributes;
use SimpleSAML\Utils\Auth;
use SimpleSAML\Utils\Config;
use SimpleSAML\Utils\HTTP;
use SimpleSAML\Utils\Random;

class Utils
{
    protected static ?Config $config = null;
    protected static ?HTTP $http = null;
    protected static ?Random $random = null;
    protected static ?Auth $auth = null;
    protected static ?Attributes $attributes = null;

    public function config(): Config
    {
        return self::$config ??= new Config();
    }

    public function http(): HTTP
    {
        return self::$http ??= new HTTP();
    }

    public function random(): Random
    {
        return self::$random ??= new Random();
    }

    public function auth(): Auth
    {
        return self::$auth ??= new Auth();
    }

    public function attributes(): Attributes
    {
        return self::$attributes ??= new Attributes();
    }
}
