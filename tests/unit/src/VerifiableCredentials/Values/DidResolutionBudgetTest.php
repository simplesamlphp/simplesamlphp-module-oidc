<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\VerifiableCredentials\Values;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\VerifiableCredentials\Values\DidResolutionBudget;
use SimpleSAML\OpenID\Did\DidDocument;
use SimpleSAML\OpenID\Did\DidUrl;

/**
 * What one Credential Request may spend on resolving the DIDs its key proofs name.
 */
#[CoversClass(DidResolutionBudget::class)]
#[AllowMockObjectsWithoutExpectations]
class DidResolutionBudgetTest extends TestCase
{
    protected function sut(int $maxNetworkResolvedDids = 2): DidResolutionBudget
    {
        return new DidResolutionBudget(microtime(true) + 15, $maxNetworkResolvedDids);
    }


    protected function didDocument(): DidDocument
    {
        return $this->createMock(DidDocument::class);
    }


    public function testCountsDistinctFetchedDidsUpToTheCap(): void
    {
        $didResolutionBudget = $this->sut(2);

        $first = new DidUrl('did:web:one.example.org#key-1');
        $second = new DidUrl('did:web:two.example.org#key-1');
        $third = new DidUrl('did:web:three.example.org#key-1');

        $this->assertTrue($didResolutionBudget->canResolve($first));
        $didResolutionBudget->noteResolutionAttempt($first);

        $this->assertTrue($didResolutionBudget->canResolve($second));
        $didResolutionBudget->noteResolutionAttempt($second);

        $this->assertFalse($didResolutionBudget->canResolve($third));
    }


    /**
     * Another key in a document already fetched costs nothing more, so it is not what the cap is about.
     */
    public function testAnotherKeyInADidAlreadyFetchedStaysWithinTheCap(): void
    {
        $didResolutionBudget = $this->sut(1);

        $didResolutionBudget->noteResolutionAttempt(new DidUrl('did:web:one.example.org#key-1'));

        $this->assertTrue($didResolutionBudget->canResolve(new DidUrl('did:web:one.example.org#key-2')));
    }


    /**
     * A failing fetch is the expensive one - it can be a full timeout - so counting only the ones which
     * succeed would let a request name a fresh unreachable host in every proof and pay for all of them.
     * The budget is therefore told about the attempt, and never about the outcome.
     */
    public function testAnAttemptCountsWhetherOrNotAnythingCameBack(): void
    {
        $didResolutionBudget = $this->sut(1);

        $didResolutionBudget->noteResolutionAttempt(new DidUrl('did:web:unreachable.example.org#key-1'));

        $this->assertFalse($didResolutionBudget->canResolve(new DidUrl('did:web:two.example.org#key-1')));
    }


    /**
     * `did:jwk` and `did:key` carry their key inside the identifier, so resolving one is decoding rather
     * than fetching. Counting them would refuse a legitimate batch: under `did:jwk` every key is its own
     * DID, so eight proofs are eight distinct DIDs.
     */
    public function testLocallyResolvedMethodsAreNotCounted(): void
    {
        $didResolutionBudget = $this->sut(1);

        foreach (['did:jwk:eyJrdHkiOiJFQyJ9#0', 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLG#z6Mkh'] as $value) {
            $didUrl = new DidUrl($value);
            $this->assertTrue($didResolutionBudget->canResolve($didUrl));
            $didResolutionBudget->noteResolutionAttempt($didUrl);
        }

        // The fetch budget is untouched by any of that.
        $this->assertTrue($didResolutionBudget->canResolve(new DidUrl('did:web:one.example.org#key-1')));
    }


    /**
     * A method the library gains later is bounded by default rather than exempt by nobody having listed
     * it, which is why the local methods are the ones named.
     */
    public function testAMethodNobodyNamedCountsAgainstTheCap(): void
    {
        $didResolutionBudget = $this->sut(1);

        $didResolutionBudget->noteResolutionAttempt(new DidUrl('did:example:abc#key-1'));

        $this->assertFalse($didResolutionBudget->canResolve(new DidUrl('did:web:one.example.org#key-1')));
    }


    /**
     * Keyed by the DID rather than by the DID URL which asked for it, because one fetch answers for
     * every key in the document. Keyed the other way, a batch naming two keys of one holder would fetch
     * the document twice while the cap counted one.
     */
    public function testRecallsADocumentForEveryKeyNamedInIt(): void
    {
        $didResolutionBudget = $this->sut();
        $didUrl = new DidUrl('did:web:one.example.org#key-1');

        $this->assertNull($didResolutionBudget->recallDocument($didUrl));

        $didDocument = $this->didDocument();
        $didResolutionBudget->rememberDocument($didUrl, $didDocument);

        $this->assertSame($didDocument, $didResolutionBudget->recallDocument($didUrl));
        $this->assertSame(
            $didDocument,
            $didResolutionBudget->recallDocument(new DidUrl('did:web:one.example.org#key-2')),
        );
        // Another DID is another document.
        $this->assertNull($didResolutionBudget->recallDocument(new DidUrl('did:web:two.example.org#key-1')));
    }


    public function testCarriesTheDeadlineItWasGiven(): void
    {
        $deadlineTimestamp = microtime(true) + 15;

        $this->assertSame(
            $deadlineTimestamp,
            (new DidResolutionBudget($deadlineTimestamp, 4))->getDeadlineTimestamp(),
        );
    }
}
