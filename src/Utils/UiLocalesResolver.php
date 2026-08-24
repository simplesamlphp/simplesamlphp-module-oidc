<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidc\Bridges\SspBridge;

/**
 * Resolve the SimpleSAMLphp UI language to use based on the OpenID Connect
 * ui_locales request parameter (space-separated list of BCP47 language tags,
 * ordered by preference).
 */
class UiLocalesResolver
{
    public function __construct(
        protected readonly Configuration $sspConfiguration,
        protected readonly SspBridge $sspBridge,
    ) {
    }


    /**
     * Get the most preferred requested language which is available in
     * SimpleSAMLphp (per the language.available config option), or null if
     * none of the requested languages are available. Matching is
     * case-insensitive, treats '-' and '_' separators as equal, and falls
     * back to the primary language subtag (requested 'fr-CA' matches
     * available 'fr'). Per specification, an unsupported (or malformed)
     * ui_locales value is not an error, so null is returned instead.
     */
    public function resolve(?string $uiLocales): ?string
    {
        if ($uiLocales === null || trim($uiLocales) === '') {
            return null;
        }

        $normalizedAvailableLanguages = [];
        foreach ($this->getAvailableLanguages() as $availableLanguage) {
            $normalizedAvailableLanguages[$this->normalize($availableLanguage)] = $availableLanguage;
        }

        foreach (preg_split('/\s+/', trim($uiLocales)) ?: [] as $languageTag) {
            $normalizedLanguageTag = $this->normalize($languageTag);

            if (isset($normalizedAvailableLanguages[$normalizedLanguageTag])) {
                return $normalizedAvailableLanguages[$normalizedLanguageTag];
            }

            $primarySubtag = explode('_', $normalizedLanguageTag)[0];
            if (isset($normalizedAvailableLanguages[$primarySubtag])) {
                return $normalizedAvailableLanguages[$primarySubtag];
            }
        }

        return null;
    }


    /**
     * Get languages available in SimpleSAMLphp, represented as BCP47 language tags (SSP uses underscore as
     * region separator in some codes, like pt_BR, while BCP47 uses hyphen). Can be used to advertise
     * supported UI locales in OP discovery metadata (ui_locales_supported).
     *
     * @return string[]
     */
    public function getSupportedUiLocales(): array
    {
        return array_map(
            fn(string $availableLanguage): string => str_replace('_', '-', $availableLanguage),
            $this->getAvailableLanguages(),
        );
    }


    /**
     * Get languages available in SimpleSAMLphp (configured in language.available and usable for UI
     * rendering), as computed by SimpleSAMLphp itself
     * (\SimpleSAML\Locale\Language::getAvailableLanguages()). This includes SimpleSAMLphp's own handling
     * of deprecated locale codes and filtering of codes unknown to the translation system, so such codes
     * are neither advertised nor matched here.
     *
     * @return string[]
     */
    protected function getAvailableLanguages(): array
    {
        return $this->sspBridge->locale()->language()->getAvailableLanguages($this->sspConfiguration);
    }


    protected function normalize(string $languageTag): string
    {
        return strtolower(str_replace('-', '_', $languageTag));
    }
}
