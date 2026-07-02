<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge\Locale;

use SimpleSAML\Locale\Language as SspLanguage;

class Language
{
    public function setLanguageCookie(string $language): void
    {
        SspLanguage::setLanguageCookie($language);
    }
}
