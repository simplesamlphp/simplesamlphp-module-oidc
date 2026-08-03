<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList\Values;

use DateTimeImmutable;
use DateTimeZone;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use Throwable;

/**
 * Reading typed values out of a database row.
 *
 * The three drivers this module supports disagree about what comes back from a query: PDO returns
 * everything as a string on some of them, integers on others, and booleans in three different shapes.
 * Normalising in one place keeps that spread of behaviour from being rediscovered in every record.
 */
trait DatabaseRowValuesTrait
{
    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected static function asString(array $row, string $key): string
    {
        return self::asNullableString($row, $key) ?? throw new StatusListException(
            sprintf('Row is missing the required column "%s".', $key),
        );
    }

    /**
     * @param array<array-key,mixed> $row
     */
    protected static function asNullableString(array $row, string $key): ?string
    {
        /** @var mixed $value */
        $value = $row[$key] ?? null;

        if ($value === null) {
            return null;
        }

        return is_scalar($value) ? (string)$value : null;
    }

    /**
     * @param array<array-key,mixed> $row
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected static function asInt(array $row, string $key): int
    {
        /** @var mixed $value */
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && preg_match('/^-?\d+$/', $value) === 1)) {
            throw new StatusListException(
                sprintf('Row column "%s" is not an integer, %s given.', $key, get_debug_type($value)),
            );
        }

        return (int)$value;
    }

    /**
     * @param array<array-key,mixed> $row
     */
    protected static function asBool(array $row, string $key): bool
    {
        /** @var mixed $value */
        $value = $row[$key] ?? false;

        // PostgreSQL can return 't' / 'f' or a real boolean, MySQL an integer, SQLite an integer or a
        // numeric string. Only the values which actually mean false are treated as false, so that an
        // unexpected shape does not quietly read as one.
        if (is_string($value)) {
            return !in_array(strtolower($value), ['', '0', 'f', 'false', 'n', 'no'], true);
        }

        return (bool)$value;
    }

    /**
     * @param array<array-key,mixed> $row
     */
    protected static function asNullableDateTime(array $row, string $key): ?DateTimeImmutable
    {
        $value = self::asNullableString($row, $key);

        if ($value === null || $value === '') {
            return null;
        }

        // Timestamps are stored in UTC and come back without a zone, so the zone is supplied here
        // rather than left to whatever the server's default happens to be.
        try {
            return new DateTimeImmutable($value, new DateTimeZone('UTC'));
        } catch (Throwable) {
            return null;
        }
    }
}
