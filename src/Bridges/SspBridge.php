<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges;

use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Module;
use SimpleSAML\Module\oidc\Bridges\SspBridge\Utils;

/**
 * SimpleSAMLphp bridge classes to make it easy to inject them as services and consequently easy unit testing.
 * It is also used to cover some static method calls in SimpleSAMLphp for some classes.
 */
class SspBridge
{
    protected static ?Auth $auth = null;
    protected static ?Utils $utils = null;
    protected static ?Module $module = null;

    public function utils(): Utils
    {
        return self::$utils ??= new Utils();
    }

    public function module(): Module
    {
        return self::$module ??= new Module();
    }

    public function auth(): Auth
    {
        return self::$auth ??= new Auth();
    }
}
