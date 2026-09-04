<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\VerifiableCredentials\Values;

use SimpleSAML\OpenID\Did\DidDocument;
use SimpleSAML\OpenID\Did\DidUrl;

/**
 * What one Credential Request is allowed to spend on resolving the DIDs its key proofs name.
 *
 * A `did:web` identifier is the only input to this module which turns into an outbound fetch to a
 * destination chosen by whoever is asking to be issued a credential. The destination policy decides
 * where those fetches may go; this decides how many of them a single request may cause and by when they
 * all have to be finished, so that a batch of proofs cannot become a batch of slow fetches held open
 * against this deployment.
 *
 * Deliberately not configurable, for the same reason the batch size is not: these are bounds on what a
 * request may cost this issuer, not a description of anything a deployment has.
 */
class DidResolutionBudget
{
    /**
     * The DID methods which resolve without leaving this process.
     *
     * Named the other way round on purpose. `did:jwk` and `did:key` carry their key inside the
     * identifier, so resolving one is decoding rather than fetching, and counting them would refuse
     * legitimate batches: under `did:jwk` every key is its own DID, so eight proofs are eight distinct
     * DIDs. Everything not named here counts against the fetch budget, so a network-backed method the
     * library adds later is bounded by default instead of being exempt by nobody having listed it.
     */
    protected const array LOCALLY_RESOLVED_DID_METHODS = ['jwk', 'key'];


    /**
     * The documents already resolved during this request, keyed by the bare DID they describe.
     *
     * Keyed by the DID rather than by the DID URL which asked for it, because one fetch answers for
     * every key in the document. Keyed the other way, a batch naming `#key-1` and `#key-2` of the same
     * `did:web` would fetch it twice while the cap counted one - so the bound this class states would
     * have been true about DIDs and false about outbound requests, which is the thing it exists to
     * limit. The library's own cache closes the same gap when one is configured; this holds without it.
     *
     * @var array<string,\SimpleSAML\OpenID\Did\DidDocument>
     */
    protected array $documentsByDid = [];

    /**
     * The DIDs this request has already sent this deployment out to fetch, whether or not the fetch
     * then succeeded.
     *
     * @var array<string,true>
     */
    protected array $attemptedNetworkDids = [];


    /**
     * @param float $deadlineTimestamp When everything this request is doing has to be finished, as a
     * unix timestamp with fractions. Passed down into each resolution, so that the fetches share one
     * bound rather than each getting the per-fetch timeout to itself.
     * @param int $maxNetworkResolvedDids How many distinct DIDs this request may send this deployment
     * out to fetch.
     */
    public function __construct(
        protected readonly float $deadlineTimestamp,
        protected readonly int $maxNetworkResolvedDids,
    ) {
    }


    public function getDeadlineTimestamp(): float
    {
        return $this->deadlineTimestamp;
    }


    /**
     * Whether resolving this DID URL is still within what the request may spend.
     *
     * A DID this request has already gone out for costs nothing more, and neither does one which
     * resolves locally.
     */
    public function canResolve(DidUrl $didUrl): bool
    {
        if (in_array($didUrl->getMethod(), self::LOCALLY_RESOLVED_DID_METHODS, true)) {
            return true;
        }

        if (array_key_exists($didUrl->getDid(), $this->attemptedNetworkDids)) {
            return true;
        }

        return count($this->attemptedNetworkDids) < $this->maxNetworkResolvedDids;
    }


    /**
     * Record that this request is about to go out for this DID.
     *
     * Recorded before the attempt rather than after it succeeds. A failing fetch is the expensive one -
     * it can be a full timeout - so counting only successes would let a request name a fresh
     * unreachable host in every proof and pay for all of them.
     */
    public function noteResolutionAttempt(DidUrl $didUrl): void
    {
        if (in_array($didUrl->getMethod(), self::LOCALLY_RESOLVED_DID_METHODS, true)) {
            return;
        }

        $this->attemptedNetworkDids[$didUrl->getDid()] = true;
    }


    /**
     * The document an earlier proof in this same request already resolved this DID to, if any.
     */
    public function recallDocument(DidUrl $didUrl): ?DidDocument
    {
        return $this->documentsByDid[$didUrl->getDid()] ?? null;
    }


    public function rememberDocument(DidUrl $didUrl, DidDocument $didDocument): void
    {
        $this->documentsByDid[$didUrl->getDid()] = $didDocument;
    }
}
