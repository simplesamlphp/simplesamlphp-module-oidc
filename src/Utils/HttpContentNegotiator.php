<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils;

/**
 * Proactive negotiation of what a response may be, as described by RFC 9110.
 *
 * Symfony's request object exposes an ordered list of acceptable media types, which answers "what would
 * this client like best" but not "would this client refuse what we have". Those differ exactly where it
 * matters here: a range weighted `q=0` appears in that list like any other, and a more specific range
 * has to override a less specific one whatever their relative weights.
 *
 * Matching ignores media type parameters on a range, so `application/x;version=2` is treated as matching
 * `application/x`. That is the lenient direction on purpose: a stricter reading only ever turns a request
 * this endpoint could have answered into a 406.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Utils\HttpContentNegotiatorTest
 */
class HttpContentNegotiator
{
    /**
     * Whether a client which sent this Accept header will take the given media type.
     *
     * An absent or empty header is no constraint at all rather than a constraint against everything,
     * which is what RFC 9110 means by the field being optional.
     */
    public function acceptsMediaType(?string $accept, string $mediaType): bool
    {
        $accept = trim((string)$accept);

        if ($accept === '') {
            return true;
        }

        $wanted = $this->splitMediaType(strtolower($mediaType));

        if ($wanted === null) {
            return false;
        }

        $bestPrecedence = -1;
        $bestWeight = 0.0;

        foreach (explode(',', $accept) as $rangeSpecification) {
            $range = $this->parseWeighted($rangeSpecification);

            if ($range === null) {
                continue;
            }

            $precedence = $this->precedenceOf($range['value'], $wanted);

            if ($precedence < 0) {
                continue;
            }

            // The most specific matching range decides, whatever its weight -- that is the whole point
            // of being able to write `*/*;q=1, application/x;q=0`, which accepts everything except one
            // thing. Weight only breaks ties between ranges of equal specificity.
            if ($precedence > $bestPrecedence || ($precedence === $bestPrecedence && $range['weight'] > $bestWeight)) {
                $bestPrecedence = $precedence;
                $bestWeight = $range['weight'];
            }
        }

        return $bestWeight > 0.0;
    }


    /**
     * The content coding to encode the body with, in the client's order of preference.
     *
     * @param string ...$supported Codings this response can produce, most preferred first. Ties go to
     * the earlier one.
     * @return ?string Null when the body should be sent unencoded, either because the client expressed
     * no preference or because it wants none of what is on offer.
     */
    public function preferredContentCoding(?string $acceptEncoding, string ...$supported): ?string
    {
        $acceptEncoding = trim((string)$acceptEncoding);

        if ($acceptEncoding === '') {
            return null;
        }

        $weights = [];
        $wildcardWeight = null;

        foreach (explode(',', $acceptEncoding) as $codingSpecification) {
            $coding = $this->parseWeighted($codingSpecification);

            if ($coding === null) {
                continue;
            }

            if ($coding['value'] === '*') {
                $wildcardWeight = $coding['weight'];

                continue;
            }

            $weights[$coding['value']] = $coding['weight'];
        }

        $best = null;
        $bestWeight = 0.0;

        foreach ($supported as $coding) {
            $weight = $weights[strtolower($coding)] ?? $wildcardWeight ?? 0.0;

            if ($weight > $bestWeight) {
                $best = $coding;
                $bestWeight = $weight;
            }
        }

        return $best;
    }


    /**
     * Splits one comma separated element into its value and its weight.
     *
     * @return ?array{value: string, weight: float}
     */
    protected function parseWeighted(string $specification): ?array
    {
        $parameters = explode(';', $specification);
        $value = strtolower(trim(array_shift($parameters)));

        if ($value === '') {
            return null;
        }

        $weight = 1.0;

        foreach ($parameters as $parameter) {
            [$name, $parameterValue] = array_pad(explode('=', $parameter, 2), 2, '');

            if (strtolower(trim($name)) !== 'q') {
                continue;
            }

            $parameterValue = trim($parameterValue, " \t\"");
            $weight = is_numeric($parameterValue) ? max(0.0, min(1.0, (float)$parameterValue)) : 1.0;

            // Everything past the weight is accept-ext, not a media type parameter, so there is no
            // second `q` to find.
            break;
        }

        return ['value' => $value, 'weight' => $weight];
    }


    /**
     * How specifically a media range names the given media type: 3 exact, 2 by type, 1 by wildcard, and
     * -1 for no match at all.
     *
     * @param array{type: string, subtype: string} $wanted
     */
    protected function precedenceOf(string $range, array $wanted): int
    {
        $parsed = $this->splitMediaType($range);

        if ($parsed === null) {
            return -1;
        }

        if ($parsed['type'] === '*' && $parsed['subtype'] === '*') {
            return 1;
        }

        if ($parsed['subtype'] === '*') {
            return $parsed['type'] === $wanted['type'] ? 2 : -1;
        }

        return $parsed['type'] === $wanted['type'] && $parsed['subtype'] === $wanted['subtype'] ? 3 : -1;
    }


    /**
     * @return ?array{type: string, subtype: string}
     */
    protected function splitMediaType(string $mediaType): ?array
    {
        $separator = strpos($mediaType, '/');

        if ($separator === false) {
            return null;
        }

        return [
            'type' => substr($mediaType, 0, $separator),
            'subtype' => substr($mediaType, $separator + 1),
        ];
    }
}
