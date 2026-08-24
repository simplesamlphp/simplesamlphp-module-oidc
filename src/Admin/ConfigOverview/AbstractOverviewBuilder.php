<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Admin\ConfigOverview;

use DateInterval;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Codebooks\ConfigOverviewValueTypeEnum;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use Throwable;

/**
 * Shared behaviour for the configuration overview screens.
 *
 * Rendering rules which must hold on every screen live here, most importantly that secret values
 * are never displayed. Concrete builders decide which options belong on their screen and how to
 * group them.
 *
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder
 * @see \SimpleSAML\Module\oidc\Admin\ConfigOverview\FederationOverviewBuilder
 */
abstract class AbstractOverviewBuilder
{
    /**
     * Placeholder shown instead of an HTTP client option value which is not on the allowlist below.
     */
    protected const string REDACTED = '(not shown)';

    /**
     * Guzzle request options which are safe to render verbatim.
     *
     * The HTTP client option arrays are passed through to Guzzle as configured, so they can carry
     * credentials: 'auth' holds basic auth user and password, 'proxy' can embed userinfo in the URL,
     * 'headers' can hold an Authorization or Cookie header, and 'cert' / 'ssl_key' can hold a
     * private key passphrase. An allowlist is used rather than a denylist of known-secret keys, so
     * that a Guzzle option added in the future does not leak by default. Redacted options still have
     * their name shown, so it stays visible that they are set.
     *
     * @see https://docs.guzzlephp.org/en/stable/request-options.html
     */
    protected const array DISPLAYABLE_HTTP_CLIENT_OPTIONS = [
        'allow_redirects',
        'connect_timeout',
        'decode_content',
        'expect',
        'force_ip_resolve',
        'http_errors',
        'read_timeout',
        'stream',
        'synchronous',
        'timeout',
        'verify',
        'version',
    ];


    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Routes $routes,
        protected readonly DateIntervalFormatter $dateIntervalFormatter,
        protected readonly LoggerService $logger,
    ) {
    }


    protected function buildDurationRow(
        string $label,
        DateInterval $duration,
        string $configOption,
        ?string $note = null,
    ): Row {
        return new Row(
            $label,
            $this->dateIntervalFormatter->toHumanReadable($duration) .
            ' (' . $this->dateIntervalFormatter->toDurationSpec($duration) . ')',
            // Composed of a count, an English unit name and the configured duration spec, so it is
            // rendered as-is rather than looked up in the message catalog.
            ConfigOverviewValueTypeEnum::RawText,
            $configOption,
            $note,
        );
    }


    /**
     * @param array<string,mixed> $options
     */
    protected function buildHttpClientOptionsRow(
        string $label,
        array $options,
        string $configOption,
        string $note,
        string $noteWhenNotSet,
    ): Row {
        // Note that the check runs against the raw options, before redaction.
        $isTlsVerificationDisabled = array_key_exists('verify', $options) && $options['verify'] === false;

        return new Row(
            $label,
            $this->redactHttpClientOptions($options),
            ConfigOverviewValueTypeEnum::Json,
            $configOption,
            $options === [] ? $noteWhenNotSet : $note,
            $isTlsVerificationDisabled ? Translate::noop(
                'TLS certificate verification is disabled, which exposes these requests to ' .
                'man-in-the-middle attacks. Never use this in production.',
            ) : null,
        );
    }


    /**
     * Replace every HTTP client option value which is not explicitly allowlisted, so that a
     * credential carried in these options can not reach the screen.
     *
     * @param array<string,mixed> $options
     * @return array<string,mixed>
     */
    protected function redactHttpClientOptions(array $options): array
    {
        $redacted = [];

        /** @var mixed $value */
        foreach ($options as $key => $value) {
            /** @psalm-suppress MixedAssignment */
            $redacted[$key] = in_array($key, self::DISPLAYABLE_HTTP_CLIENT_OPTIONS, true) ?
            $value :
            self::REDACTED;
        }

        return $redacted;
    }


    /**
     * Row reporting how many secret values are configured, without disclosing any of them.
     */
    protected function buildSecretCountRow(
        string $label,
        int $count,
        string $configOption,
        ?string $note,
        ?string $warning = null,
    ): Row {
        return new Row(
            $label,
            $count === 0 ? Translate::noop('None configured') : (string)$count,
            $count === 0 ? ConfigOverviewValueTypeEnum::Text : ConfigOverviewValueTypeEnum::RawText,
            $configOption,
            $note,
            $warning,
        );
    }


    /**
     * Row showing this entity's issuer, which both screens display.
     *
     * getIssuer() throws when neither the option nor the derived host yields a value, so it is
     * resolved defensively like any other option which can fail.
     *
     * @param ?string $noteWhenConfigured Note to show when the issuer is explicitly configured.
     * @param string $noteWhenDerived Note to show when it is derived from the current HTTP host.
     */
    protected function buildIssuerRow(?string $noteWhenConfigured, string $noteWhenDerived): Row
    {
        $issuer = null;
        $isConfigured = false;
        $error = null;

        try {
            $issuer = $this->moduleConfig->getIssuer();
            // Must stay inside the guard: isIssuerConfigured() reads the same option through
            // getOptionalString(), which itself throws when the configured value is not a string.
            $isConfigured = $this->moduleConfig->isIssuerConfigured();
        } catch (Throwable $exception) {
            $error = $this->describeResolutionError($exception, ModuleConfig::OPTION_ISSUER);
        }

        return new Row(
            Translate::noop('Issuer'),
            $issuer ?? Translate::noop('N/A'),
            // A resolved issuer is data, the 'N/A' placeholder is UI text.
            is_null($issuer) ? ConfigOverviewValueTypeEnum::Text : ConfigOverviewValueTypeEnum::RawText,
            ModuleConfig::OPTION_ISSUER,
            // On failure neither note applies: the value is configured, it is simply unusable.
            is_null($error) ? ($isConfigured ? $noteWhenConfigured : $noteWhenDerived) : null,
            $error,
        );
    }


    /**
     * Row for an optional single-value entity metadata parameter.
     */
    protected function buildOptionalTextRow(
        string $label,
        ?string $value,
        string $configOption,
        ?string $note = null,
    ): Row {
        return new Row(
            $label,
            $value ?? Translate::noop('N/A'),
            // A configured value is data, the 'N/A' placeholder is UI text.
            is_null($value) ? ConfigOverviewValueTypeEnum::Text : ConfigOverviewValueTypeEnum::RawText,
            $configOption,
            $note,
        );
    }


    /**
     * Row for an optional URI, rendered as a link when set.
     */
    protected function buildOptionalUrlRow(
        string $label,
        ?string $value,
        string $configOption,
        ?string $note = null,
    ): Row {
        return new Row(
            $label,
            $value ?? Translate::noop('N/A'),
            is_null($value) ? ConfigOverviewValueTypeEnum::Text : ConfigOverviewValueTypeEnum::Url,
            $configOption,
            $note,
        );
    }


    /**
     * Build a row defensively.
     *
     * Almost every ModuleConfig getter can throw on a malformed value: getOptionalArray() and
     * getOptionalBoolean() reject the wrong type, and the duration getters hand their value to
     * DateInterval. Since these screens exist to diagnose bad configuration, a row must fail on its
     * own rather than take the page down, so any row whose value comes from such a getter is built
     * through here.
     *
     * @param callable():\SimpleSAML\Module\oidc\Admin\ConfigOverview\Row $buildRow
     */
    protected function guardRow(string $label, string $configOption, callable $buildRow): Row
    {
        try {
            return $buildRow();
        } catch (Throwable $exception) {
            return new Row(
                $label,
                Translate::noop('N/A'),
                ConfigOverviewValueTypeEnum::Text,
                $configOption,
                null,
                $this->describeResolutionError($exception, $configOption),
            );
        }
    }


    /**
     * Report a config option which could not be resolved, and return a row warning for it.
     *
     * These screens are what an administrator opens when something is misconfigured, so a broken
     * option must be reported in place rather than take the whole page down. Callers catch the
     * throwable themselves, which keeps the resolved value's type intact.
     *
     * The exception message is deliberately NOT rendered. It comes from config validation and, for
     * key pairs, from the underlying openid library while it loads key material, so it can quote
     * configured values back verbatim. That would defeat the never-render-secrets rule this class
     * exists to enforce. The detail goes to the log instead, and the screen only points at it.
     */
    protected function describeResolutionError(Throwable $exception, string $configOption): string
    {
        $this->logger->error(
            sprintf(
                'Configuration overview could not resolve option "%s": %s',
                $configOption,
                $exception->getMessage(),
            ),
            ['exceptionClass' => $exception::class],
        );

        return Translate::noop(
            'This option could not be resolved, so what is shown here may be incomplete. The reason ' .
            'was written to the SimpleSAMLphp log.',
        );
    }


    protected function yesNo(bool $value): string
    {
        return $value ? Translate::noop('Yes') : Translate::noop('No');
    }


    protected function formatBytes(int $bytes): string
    {
        if ($bytes >= 1048576) {
            return sprintf('%d B (%s MB)', $bytes, $this->formatDecimal($bytes / 1048576));
        }

        if ($bytes >= 1024) {
            return sprintf('%d B (%s KB)', $bytes, $this->formatDecimal($bytes / 1024));
        }

        return sprintf('%d B', $bytes);
    }


    /**
     * Render a number with at most one decimal place, dropping a trailing '.0'.
     */
    protected function formatDecimal(float $value): string
    {
        return rtrim(rtrim(number_format($value, 1, '.', ''), '0'), '.');
    }
}
