<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Module\oidc\Bridges\SspBridge\Locale\Language;

class Locale
{
    protected static ?Language $language = null;

    public function language(): Language
    {
        return self::$language ??= new Language();
    }
}
