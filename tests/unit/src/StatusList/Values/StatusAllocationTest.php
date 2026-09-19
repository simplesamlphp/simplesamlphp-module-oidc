<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList\Values;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\StatusList\Values\StatusAllocation;
use SimpleSAML\OpenID\TokenStatusList\StatusReference;

/**
 * What the index allocator answers: the storage key of the list the index was claimed in, and the
 * reference to that index as a Relying Party will use it.
 *
 * `CredentialStatusIssuer` reads the URI and the index off it to build the credential's `status` claim,
 * and logs the list ID and the index; the reference itself is carried whole, though nothing in `src/`
 * reads it as one today. The URI and the index are the reference's own, read through, so the two
 * accessors answer with the values the reference was built with.
 */
#[CoversClass(StatusAllocation::class)]
class StatusAllocationTest extends TestCase
{
    protected const string STATUS_LIST_ID = '0f3c9a71';

    protected const string URI = 'https://op.example.org/status-list/0f3c9a71';

    protected const int IDX = 1234;


    public function testCarriesTheListAndTheReferenceAndReadsTheReferenceThrough(): void
    {
        $statusReference = new StatusReference(self::URI, self::IDX);

        $allocation = new StatusAllocation(self::STATUS_LIST_ID, $statusReference);

        $this->assertSame(self::STATUS_LIST_ID, $allocation->getStatusListId());
        $this->assertSame($statusReference, $allocation->getStatusReference());
        $this->assertSame(self::URI, $allocation->getUri());
        $this->assertSame(self::IDX, $allocation->getIdx());
    }
}
