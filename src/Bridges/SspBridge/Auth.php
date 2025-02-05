<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Module\oidc\Bridges\SspBridge\Auth\Source;

class Auth
{
    protected static ?Source $source = null;

    public function source(): Source
    {
        return self::$source ??= new Source();
    }
}
