<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;

/**
 * A single label / value pair shown on a configuration overview screen.
 *
 * The $configOption property records which ModuleConfig::OPTION_* constant this row displays, so
 * that a test can assert every option is either shown somewhere or explicitly excluded. Rows which
 * do not correspond to a config option (for example, endpoint URLs) simply leave it null.
 *
 * IMPORTANT: rows must never carry secret values (encryption keys, initial access tokens, API
 * tokens, cache adapter credentials, private key passwords). For such options, show whether they
 * are configured, not what they are set to.
 */
class Row
{
    public function __construct(
        protected readonly string $label,
        protected readonly mixed $value,
        protected readonly ConfigOverviewValueTypeEnum $valueType = ConfigOverviewValueTypeEnum::Text,
        protected readonly ?string $configOption = null,
        protected readonly ?string $note = null,
        protected readonly ?string $warning = null,
    ) {
    }


    public function getLabel(): string
    {
        return $this->label;
    }


    public function getValue(): mixed
    {
        return $this->value;
    }


    public function getValueType(): ConfigOverviewValueTypeEnum
    {
        return $this->valueType;
    }


    /**
     * The ModuleConfig::OPTION_* value this row displays, or null if the row is not tied to a
     * single config option.
     */
    public function getConfigOption(): ?string
    {
        return $this->configOption;
    }


    /**
     * Additional context, for example, that the shown value is a fallback rather than a configured
     * one.
     */
    public function getNote(): ?string
    {
        return $this->note;
    }


    /**
     * Set when the current value warrants administrator attention, typically a security relevant
     * setting which deviates from the safe default.
     */
    public function getWarning(): ?string
    {
        return $this->warning;
    }
}
