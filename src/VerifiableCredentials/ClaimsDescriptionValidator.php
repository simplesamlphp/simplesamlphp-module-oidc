<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials;

use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * Claims description objects (OpenID4VCI 1.0 Appendix B), as a wallet sends them in authorization details (B.1)
 * and as this issuer publishes them in a credential configuration (B.2). Both are held to the same processing
 * rules (B.3), so the check is one, and each caller names what the descriptions belong to in the reasons it gets.
 */
class ClaimsDescriptionValidator
{
    /**
     * Why the claims descriptions can not be accepted, or null when they can: a non-empty array of claims
     * description objects, each with a path which is a claims path pointer (Appendix C) and, if it has one, a
     * boolean mandatory; none repeating or contradicting another (Appendix B.3).
     *
     * The pointers are laid out in a tree, one node per path prefix, which tells a repeated or contradictory
     * description in one pass over the paths, however many there are. A node addressed by two pointers is a claim
     * described twice. A node continued by two kinds of component is read two ways: by null (every element of an
     * array) and by an index (one element), or by a member name (an object) and by null or an index (an array).
     *
     * @param string $of What the descriptions belong to, as the reasons name it: "an authorization detail".
     */
    public function findFaultInClaimsDescriptions(mixed $claimsDescriptions, string $of): ?string
    {
        if (! $this->isNonEmptyJsonArray($claimsDescriptions)) {
            return 'The claims of ' . $of . ' are not a non-empty array of claims descriptions.';
        }

        // Edges keyed by parent node, kind and value; the root is node 0. A node is continued by one kind of
        // component, or the descriptions contradict each other.
        $childNodes = [];
        $continuationKindOf = [];
        $addressedNodes = [];
        $nextNode = 1;

        /** @psalm-suppress MixedAssignment */
        foreach ($claimsDescriptions as $claimsDescription) {
            if (! $this->isJsonObject($claimsDescription)) {
                return 'A claims description of ' . $of . ' is not a JSON object.';
            }

            /** @psalm-suppress MixedAssignment */
            $path = $claimsDescription[ClaimsEnum::Path->value] ?? null;

            if (! $this->isClaimsPathPointer($path)) {
                return 'A claims description of ' . $of . ' has no path which is a claims path pointer: a ' .
                'non-empty array of strings, nulls and non-negative integers.';
            }

            if (
                array_key_exists(ClaimsEnum::Mandatory->value, $claimsDescription) &&
                ! is_bool($claimsDescription[ClaimsEnum::Mandatory->value])
            ) {
                return 'The mandatory member of a claims description of ' . $of . ' is not a boolean.';
            }

            $node = 0;
            foreach ($path as $component) {
                $kind = match (true) {
                    is_string($component) => 'member',
                    $component === null => 'all',
                    default => 'index',
                };

                $continuationKindOf[$node] ??= $kind;
                if ($continuationKindOf[$node] !== $kind) {
                    return 'Two claims descriptions of ' . $of . ' contradict each other: one addresses an ' .
                    'object member where another addresses an array, or all elements of an array where another ' .
                    'addresses one of them.';
                }

                $edge = $node . "\x00" . $kind . "\x00" . (string)$component;
                $node = $childNodes[$edge] ??= $nextNode++;
            }

            if (isset($addressedNodes[$node])) {
                return 'Two claims descriptions of ' . $of . ' address the same claim.';
            }
            $addressedNodes[$node] = true;
        }

        return null;
    }


    /**
     * A claims path pointer into a JSON-based credential, the only kind this issuer issues (OpenID4VCI 1.0
     * Appendix C.1): a non-empty array of strings (a member), nulls (every element of an array) and non-negative
     * integers (one element).
     *
     * @psalm-assert-if-true non-empty-list<string|int|null> $path
     */
    public function isClaimsPathPointer(mixed $path): bool
    {
        if (! $this->isNonEmptyJsonArray($path)) {
            return false;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($path as $component) {
            if (! (is_string($component) || $component === null || (is_int($component) && $component >= 0))) {
                return false;
            }
        }

        return true;
    }


    /**
     * A JSON object as it decodes to a PHP array: one with named members. An empty object decodes to an empty array,
     * and is taken as one too; it has none of the members a detail or a claims description requires.
     *
     * @psalm-assert-if-true mixed[] $value
     */
    public function isJsonObject(mixed $value): bool
    {
        return is_array($value) && ($value === [] || ! array_is_list($value));
    }


    /**
     * A JSON array with at least one element, as it decodes to a PHP array.
     *
     * @psalm-assert-if-true non-empty-list<mixed> $value
     */
    public function isNonEmptyJsonArray(mixed $value): bool
    {
        return is_array($value) && $value !== [] && array_is_list($value);
    }
}
