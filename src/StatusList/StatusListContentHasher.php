<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\StatusList;

/**
 * Hash of the content a Status List Token was signed over.
 *
 * This is what makes staleness detectable without reconstructing the list. The path which changes a
 * status clears the stored hash right after changing it, and the path which serves a list re-signs when
 * the stored hash is empty. So the entries are only ever read when a token is actually being produced,
 * rather than on every request in order to work out whether one is needed.
 *
 * It also settles which of several concurrent signers wins: publication is a compare-and-set against the
 * hash the signer observed before it started, so a signer whose snapshot was superseded finds the row no
 * longer matching and discards its token instead of overwriting a newer one.
 *
 * Only what the published token conveys is hashed. Allocating an index touches an entry without changing
 * what the list says about it -- a newly allocated index is Valid, exactly as it was while free -- so
 * allocation deliberately does not invalidate anything.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\StatusList\StatusListContentHasherTest
 */
class StatusListContentHasher
{
    /**
     * Identifies how the input below is framed.
     *
     * A hash produced here is only ever compared against another produced here, so the framing is free
     * to change -- but changing it must not let a hash written by an older release be read as still
     * matching. Bumping this makes every stored hash stop matching at once, so every list re-signs
     * once and nothing is served in the meantime which misrepresents its content.
     */
    final public const string VERSION = 'v1';


    /**
     * @param array<int,int> $nonValidStatuses Index to status for every entry which is not Valid. Every
     * index absent from this map is Valid, including the ones never allocated, which is the same
     * convention the published list itself follows.
     */
    public function hash(int $bits, int $capacity, array $nonValidStatuses): string
    {
        // Sorted here rather than assumed of the caller. The query producing this orders by index, but
        // the hash has to come out identical in every process and on every driver for a compare-and-set
        // against it to mean anything, and a map which arrived in another order would otherwise hash
        // differently while describing exactly the same list.
        ksort($nonValidStatuses);

        $entries = [];

        foreach ($nonValidStatuses as $idx => $status) {
            $entries[] = $idx . ':' . $status;
        }

        // Every part is labelled and delimited rather than run together. Plain concatenation is
        // ambiguous -- 1 bit with a capacity of 12 and 11 bits with a capacity of 2 would produce the
        // same input -- so two lists saying different things could agree on a hash, and one of them
        // would then keep serving a token which does not describe it.
        return hash('sha256', sprintf(
            '%s|bits=%d|capacity=%d|%s',
            self::VERSION,
            $bits,
            $capacity,
            implode(',', $entries),
        ));
    }
}
