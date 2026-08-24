<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge\Locale;

use SimpleSAML\Configuration;
use SimpleSAML\Locale\Language as SspLanguage;

class Language
{
    public function setLanguageCookie(string $language): void
    {
        SspLanguage::setLanguageCookie($language);
    }


    public function getLanguageCookie(): ?string
    {
        return SspLanguage::getLanguageCookie();
    }


    /**
     * Get the languages available in SimpleSAMLphp (configured in language.available and known to the
     * translation system), as computed by SimpleSAMLphp itself. The Language instance is created without
     * handling the language request parameter, so that querying it does not trigger side effects like
     * switching the current language or setting the language cookie.
     *
     * @return string[]
     */
    public function getAvailableLanguages(Configuration $configuration): array
    {
        return (new SspLanguage($configuration, handleLanguageRequestParameter: false))
            ->getAvailableLanguages();
    }
}
