<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc;

use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\Helpers\Http;

class Helpers
{
    protected static ?Http $http = null;
    protected static ?Client $client = null;

    public function http(): Http
    {
        return static::$http ??= new Http();
    }

    public function client(): Client
    {
        return static::$client ??= new Client(
            $this->http(),
        );
    }
}
