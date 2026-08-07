<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\StatusList;

use DateInterval;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Repositories\StatusAuditRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\StatusList\Contracts\StatusUpdaterInterface;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusService;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(CredentialStatusService::class)]
class CredentialStatusServiceTest extends TestCase
{
    protected const string CREDENTIAL_ID = 'https://issuer.example.org/vc/abc';

    protected const string CREDENTIAL_ID_HASH = 'a-hash';

    protected const string LIST_ID = 'list-1';

    protected const int IDX = 42;

    protected MockObject $statusListEntryRepositoryMock;
    protected MockObject $statusUpdaterMock;
    protected MockObject $statusAuditRepositoryMock;
    protected MockObject $loggerServiceMock;
    protected Helpers $helpers;

    protected function setUp(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('hashCredentialId')->willReturn(self::CREDENTIAL_ID_HASH);
        $this->statusUpdaterMock = $this->createMock(StatusUpdaterInterface::class);
        $this->statusAuditRepositoryMock = $this->createMock(StatusAuditRepository::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->helpers = new Helpers();
    }

    protected function sut(): CredentialStatusService
    {
        return new CredentialStatusService(
            $this->statusListEntryRepositoryMock,
            $this->statusUpdaterMock,
            $this->statusAuditRepositoryMock,
            $this->helpers,
            $this->loggerServiceMock,
        );
    }

    protected function entry(
        int $status = StatusTypeEnum::Valid->value,
        bool $isAllocated = true,
        ?DateTimeImmutable $expiresAt = null,
    ): MockObject {
        $entry = $this->createMock(StatusListEntryRecord::class);
        $entry->method('getStatusListId')->willReturn(self::LIST_ID);
        $entry->method('getIdx')->willReturn(self::IDX);
        $entry->method('getStatus')->willReturn($status);
        $entry->method('isAllocated')->willReturn($isAllocated);
        $entry->method('getExpiresAt')->willReturn($expiresAt);

        return $entry;
    }

    /**
     * @throws \Exception
     */
    public function testChangesTheStatusOfTheEntryTheCredentialSitsIn(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());
        $this->statusUpdaterMock->expects($this->once())
            ->method('setStatus')
            ->with(self::LIST_ID, self::IDX, StatusTypeEnum::Invalid)
            ->willReturn(true);

        $change = $this->sut()->setStatus(
            self::CREDENTIAL_ID,
            StatusTypeEnum::Invalid,
            StatusChangeSourceEnum::Api,
            'HR system',
        );

        $this->assertTrue($change?->isChanged());
        $this->assertSame(StatusTypeEnum::Invalid, $change->getStatus());
        $this->assertSame(StatusTypeEnum::Valid->value, $change->getPreviousStatus());
    }

    /**
     * Nothing here is atomic, so the ordering decides which way the two writes may disagree. Recording
     * first leaves a row for a change which did not take effect, which reconciliation can find. The
     * other order loses the record of one which did, and nothing would ever reveal it.
     *
     * @throws \Exception
     */
    public function testRecordsTheChangeBeforeApplyingIt(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());

        $order = [];
        $this->statusAuditRepositoryMock->method('record')->willReturnCallback(
            function () use (&$order): string {
                $order[] = 'audit';

                return 'an-audit-row-id';
            },
        );
        $this->statusUpdaterMock->method('setStatus')->willReturnCallback(
            function () use (&$order): bool {
                $order[] = 'update';

                return true;
            },
        );

        $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api);

        $this->assertSame(['audit', 'update'], $order);
    }

    /**
     * @throws \Exception
     */
    public function testRecordsWhoAskedAndTheStatusItObserved(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')
            ->willReturn($this->entry(StatusTypeEnum::Suspended->value));
        $this->statusUpdaterMock->method('setStatus')->willReturn(true);

        $this->statusAuditRepositoryMock->expects($this->once())
            ->method('record')
            ->with(
                self::CREDENTIAL_ID_HASH,
                self::LIST_ID,
                self::IDX,
                StatusTypeEnum::Suspended->value,
                StatusTypeEnum::Invalid->value,
                StatusChangeSourceEnum::Api,
                'HR system',
            );

        $this->sut()->setStatus(
            self::CREDENTIAL_ID,
            StatusTypeEnum::Invalid,
            StatusChangeSourceEnum::Api,
            'HR system',
        );
    }

    /**
     * The credential identifier is a durable, externally held value; the trail stores only its hash so
     * that it does not outlive the linkage which is deliberately deleted at expiry.
     *
     * @throws \Exception
     */
    public function testTheAuditTrailNeverSeesTheCredentialIdentifier(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());
        $this->statusUpdaterMock->method('setStatus')->willReturn(true);

        $this->statusAuditRepositoryMock->expects($this->once())
            ->method('record')
            ->with($this->logicalNot($this->equalTo(self::CREDENTIAL_ID)));

        $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api);
    }

    /**
     * A caller which never saw the answer to its request repeats it. That is a success, and it writes
     * nothing: the change it is repeating was recorded when it first happened.
     *
     * @throws \Exception
     */
    public function testRepeatingARequestChangesNothingAndRecordsNothing(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')
            ->willReturn($this->entry(StatusTypeEnum::Invalid->value));

        $this->statusAuditRepositoryMock->expects($this->never())->method('record');
        $this->statusUpdaterMock->expects($this->never())->method('setStatus');

        $change = $this->sut()->setStatus(
            self::CREDENTIAL_ID,
            StatusTypeEnum::Invalid,
            StatusChangeSourceEnum::Api,
        );

        // Still the status that was asked for, so still a success -- just not this call's doing.
        $this->assertFalse($change?->isChanged());
        $this->assertSame(StatusTypeEnum::Invalid, $change->getStatus());
    }

    /**
     * @throws \Exception
     */
    public function testReportsNothingToActOnForAnUnknownCredential(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn(null);

        $this->assertNull(
            $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api),
        );
    }

    /**
     * Every index of a list exists as a row from the moment the list is created, so an unallocated row
     * describes no credential at all.
     *
     * @throws \Exception
     */
    public function testReportsNothingToActOnForAnUnallocatedEntry(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')
            ->willReturn($this->entry(isAllocated: false));

        $this->assertNull(
            $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api),
        );
    }

    /**
     * An expired credential is already refused on its own claims, so withdrawing it changes nothing
     * that is not already true. It is answered the same way as an unknown one, which is also what will
     * happen once the linkage is deleted at expiry.
     *
     * @throws \Exception
     */
    public function testReportsNothingToActOnForAnExpiredCredential(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn(
            $this->entry(expiresAt: $this->helpers->dateTime()->getUtc()->sub(new DateInterval('PT1S'))),
        );

        $this->statusUpdaterMock->expects($this->never())->method('setStatus');

        $this->assertNull(
            $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api),
        );
    }

    /**
     * @throws \Exception
     */
    public function testActsOnACredentialWhichHasNotExpiredYet(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn(
            $this->entry(expiresAt: $this->helpers->dateTime()->getUtc()->add(new DateInterval('P1D'))),
        );
        $this->statusUpdaterMock->method('setStatus')->willReturn(true);

        $this->assertNotNull(
            $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api),
        );
    }

    /**
     * Raised, not swallowed: the caller has to be told the credential does not hold what it asked for.
     *
     * @throws \Exception
     */
    public function testRaisesAFailureToApplyTheChange(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());
        $this->statusUpdaterMock->method('setStatus')
            ->willThrowException(new StatusConflictException('kept losing'));

        $this->expectException(StatusConflictException::class);

        $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api);
    }

    /**
     * Whether a list can carry a status is fixed when the list is created, so this is not a change
     * which failed but one which was never possible. Recording it would leave a permanent row
     * describing a transition that could not have happened, indistinguishable from one that did.
     *
     * @throws \Exception
     */
    public function testRecordsNothingForAStatusTheListCouldNeverCarry(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());
        $this->statusUpdaterMock->method('enforceCanRepresent')
            ->willThrowException(new UnsupportedStatusException('one bit per entry'));

        $this->statusAuditRepositoryMock->expects($this->never())->method('record');
        $this->statusUpdaterMock->expects($this->never())->method('setStatus');

        $this->expectException(UnsupportedStatusException::class);

        $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Suspended, StatusChangeSourceEnum::Api);
    }

    /**
     * A change which is recorded and then lost leaves a row someone has to find. Naming it in the log
     * is the difference between finding it and hunting by timestamp.
     *
     * @throws \Exception
     */
    public function testNamesTheAuditRowItLeftBehindWhenTheChangeFails(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn($this->entry());
        $this->statusAuditRepositoryMock->method('record')->willReturn('an-audit-row-id');
        $this->statusUpdaterMock->method('setStatus')
            ->willThrowException(new StatusConflictException('kept losing'));

        $this->loggerServiceMock->expects($this->once())
            ->method('error')
            ->with(
                $this->anything(),
                $this->callback(
                    static fn(array $context): bool => ($context['auditId'] ?? null) === 'an-audit-row-id',
                ),
            );

        $this->expectException(StatusConflictException::class);

        $this->sut()->setStatus(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Api);
    }

    /**
     * @throws \Exception
     */
    public function testReportsTheStatusACredentialHolds(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')
            ->willReturn($this->entry(StatusTypeEnum::Suspended->value));

        $this->assertSame(StatusTypeEnum::Suspended->value, $this->sut()->getStatusValue(self::CREDENTIAL_ID));
    }

    /**
     * @throws \Exception
     */
    public function testReportsNoStatusForACredentialItCanNotActOn(): void
    {
        $this->statusListEntryRepositoryMock->method('findByCredentialIdHash')->willReturn(null);

        $this->assertNull($this->sut()->getStatusValue(self::CREDENTIAL_ID));
    }
}
