<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc;

use SimpleSAML\Module\oidc\Helpers\Http;

class Helpers
{
    protected static ?Http $http = null;

    public function http(): Http
    {
        return static::$http ??= new Http();
    }
}
