<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc;

use SimpleSAML\Module\oidc\Helpers\Client;
use SimpleSAML\Module\oidc\Helpers\DateTime;
use SimpleSAML\Module\oidc\Helpers\Http;
use SimpleSAML\Module\oidc\Helpers\Str;

class Helpers
{
    protected static ?Http $http = null;
    protected static ?Client $client = null;
    protected static ?DateTime $dateTIme = null;
    protected static ?Str $str = null;

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

    public function dateTime(): DateTime
    {
        return static::$dateTIme ??= new DateTime();
    }

    public function str(): Str
    {
        return static::$str ??= new Str();
    }
}
