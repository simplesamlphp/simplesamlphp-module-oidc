<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Utils;

/**
 * Resolves a single user identifier value from a set of released attributes,
 * given an ordered list of candidate attribute names.
 *
 * In heterogeneous IdP scenarios (e.g. eduGAIN inter-federation) not every IdP
 * releases the same identifier attribute. The candidate list is therefore
 * consulted in priority order and the first candidate that is present and holds
 * a non-empty value is used.
 */
class UserIdentifierResolver
{
    /**
     * @param string[] $candidates Ordered list of candidate attribute names.
     * @param array<array-key, mixed> $attributes Released attributes (each value an array of values).
     * @return string|null The first resolved identifier value, or null if none of the candidates match.
     */
    public function resolve(array $candidates, array $attributes): ?string
    {
        foreach ($candidates as $candidate) {
            if (
                !array_key_exists($candidate, $attributes) ||
                !is_array($attributes[$candidate]) ||
                $attributes[$candidate] === []
            ) {
                continue;
            }

            /** @psalm-suppress MixedAssignment */
            $value = reset($attributes[$candidate]);

            if (is_scalar($value) && (string)$value !== '') {
                return (string)$value;
            }
        }

        return null;
    }
}
