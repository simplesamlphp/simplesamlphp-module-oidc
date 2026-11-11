<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\StatusList\CredentialOfferLinker;

#[CoversClass(CredentialOfferLinker::class)]
class CredentialOfferLinkerTest extends TestCase
{
    protected const string OFFER_ID = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';


    /**
     * The credentials are named by the hash their entries are found by, as the entries' repository makes it.
     */
    public function testLinksTheCredentialsByTheHashTheirEntriesAreFoundBy(): void
    {
        $repository = $this->createMock(StatusListEntryRepository::class);
        $repository->method('hashCredentialId')
            ->willReturnCallback(static fn(string $credentialId): string => 'hash-of-' . $credentialId);
        $repository->expects($this->once())->method('linkToOffer')
            ->with(self::OFFER_ID, ['hash-of-urn:vc:1', 'hash-of-urn:vc:2'])
            ->willReturn(2);

        $this->assertSame(2, (new CredentialOfferLinker($repository))->link(self::OFFER_ID, ['urn:vc:1', 'urn:vc:2']));
    }


    /**
     * What the repository reports linked is what the caller compares with what it signed, so it is passed on as it
     * is, a short count included.
     */
    public function testReportsHowManyCredentialsTheRepositoryLinked(): void
    {
        $repository = $this->createStub(StatusListEntryRepository::class);
        $repository->method('hashCredentialId')->willReturnArgument(0);
        $repository->method('linkToOffer')->willReturn(1);

        $this->assertSame(1, (new CredentialOfferLinker($repository))->link(self::OFFER_ID, ['urn:vc:1', 'urn:vc:2']));
    }


    public function testWritesNothingForNoCredentials(): void
    {
        $repository = $this->createMock(StatusListEntryRepository::class);
        $repository->expects($this->never())->method('linkToOffer');

        $this->assertSame(0, (new CredentialOfferLinker($repository))->link(self::OFFER_ID, []));
    }


    /**
     * The Credential Endpoint is given this rather than the entries' repository, so that issuance can not change
     * the status of a credential (OpenID4VCI 1.0 section 14.3). Linking is all it asks of the repository.
     */
    public function testAsksTheRepositoryForNothingButHashingAndLinking(): void
    {
        $called = [];
        $repository = $this->createStub(StatusListEntryRepository::class);

        foreach ((new ReflectionClass(StatusListEntryRepository::class))->getMethods() as $method) {
            if (!$method->isPublic() || $method->isConstructor() || $method->isStatic()) {
                continue;
            }

            $name = $method->getName();
            $repository->method($name)->willReturnCallback(
                function () use ($name, &$called): mixed {
                    $called[] = $name;

                    return match ($name) {
                        'hashCredentialId' => 'a-hash',
                        'linkToOffer' => 1,
                        default => null,
                    };
                },
            );
        }

        (new CredentialOfferLinker($repository))->link(self::OFFER_ID, ['urn:vc:1']);

        $this->assertSame(['hashCredentialId', 'linkToOffer'], $called);
    }
}
