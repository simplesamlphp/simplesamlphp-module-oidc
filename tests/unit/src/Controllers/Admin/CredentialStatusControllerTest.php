<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SimpleSAML\Auth\Simple;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\CredentialStatusController;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
use SimpleSAML\Module\oidc\Exceptions\StatusListException;
use SimpleSAML\Module\oidc\Exceptions\UnsupportedStatusException;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\FormFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Forms\CredentialStatusForm;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\StatusListEntryRepository;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\StatusList\CredentialStatusService;
use SimpleSAML\Module\oidc\StatusList\SubjectRefHasher;
use SimpleSAML\Module\oidc\StatusList\Values\CredentialStatusChange;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord;
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(CredentialStatusController::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialStatusControllerTest extends TestCase
{
    protected const string CREDENTIAL_ID = 'https://op.example.org/vc/abc';

    protected const string CREDENTIAL_ID_HASH = 'a-credential-id-hash';

    protected const string SUBJECT_REF = 'a-subject-ref';

    protected const string LIST_ID = 'a-status-list-id';


    protected MockObject $moduleConfigMock;

    protected MockObject $templateFactoryMock;

    protected MockObject $authorizationMock;

    protected MockObject $statusListEntryRepositoryMock;

    protected MockObject $statusListRepositoryMock;

    protected MockObject $credentialStatusServiceMock;

    protected MockObject $subjectRefHasherMock;

    protected MockObject $formFactoryMock;

    protected MockObject $formMock;

    protected MockObject $sessionMessagesServiceMock;

    protected MockObject $authSimpleFactoryMock;

    protected MockObject $authSimpleMock;

    protected MockObject $routesMock;

    protected MockObject $loggerMock;

    /** @var array<string,mixed> Data the controller handed to the template. */
    protected array $templateData = [];

    /** @var string[] Messages the controller left for the administrator. */
    protected array $messages = [];


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getUserIdentifierAttributes')->willReturn(['uid']);

        $this->templateData = [];
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (string $templateName, array $data = []): Template {
                $this->templateData = $data;

                return $this->createMock(Template::class);
            },
        );

        $this->authorizationMock = $this->createMock(Authorization::class);

        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('hashCredentialId')->willReturn(self::CREDENTIAL_ID_HASH);
        $this->statusListEntryRepositoryMock->method('findAllocatedPaginated')->willReturn(
            ['items' => [], 'total' => 0, 'numPages' => 1, 'currentPage' => 1],
        );
        $this->statusListEntryRepositoryMock->method('countNeverRetiringLists')->willReturn(0);

        $this->statusListRepositoryMock = $this->createMock(StatusListRepository::class);
        $this->credentialStatusServiceMock = $this->createMock(CredentialStatusService::class);

        $this->subjectRefHasherMock = $this->createMock(SubjectRefHasher::class);
        $this->subjectRefHasherMock->method('hash')->willReturn(self::SUBJECT_REF);

        $this->formMock = $this->createMock(CredentialStatusForm::class);
        $this->formMock->method('isSuccess')->willReturn(true);
        $this->formMock->method('getValues')->willReturn([
            CredentialStatusForm::FIELD_CREDENTIAL_ID => self::CREDENTIAL_ID,
            CredentialStatusForm::FIELD_STATUS => StatusTypeEnum::Invalid->value,
        ]);

        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->formFactoryMock->method('build')->willReturn($this->formMock);

        $this->messages = [];
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->sessionMessagesServiceMock->method('addMessage')->willReturnCallback(
            function (string $message): void {
                $this->messages[] = $message;
            },
        );

        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(false);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactoryMock->method('forAuthSourceId')->willReturn($this->authSimpleMock);

        $this->routesMock = $this->createMock(Routes::class);
        $this->routesMock->method('urlAdminCredentialStatusChange')->willReturn('https://op.example.org/change');
        $this->routesMock->method('newRedirectResponseToModuleUrl')->willReturnCallback(
            static fn(string $resource = '', array $parameters = []): RedirectResponse => new RedirectResponse(
                'https://op.example.org/' . $resource . '?' . http_build_query($parameters),
            ),
        );

        $this->loggerMock = $this->createMock(LoggerService::class);
    }


    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    protected function sut(): CredentialStatusController
    {
        return new CredentialStatusController(
            $this->moduleConfigMock,
            $this->templateFactoryMock,
            $this->authorizationMock,
            $this->statusListEntryRepositoryMock,
            $this->statusListRepositoryMock,
            $this->credentialStatusServiceMock,
            $this->subjectRefHasherMock,
            $this->formFactoryMock,
            $this->sessionMessagesServiceMock,
            $this->authSimpleFactoryMock,
            $this->userIdentifierResolver(),
            $this->routesMock,
            $this->loggerMock,
        );
    }


    protected function userIdentifierResolver(): UserIdentifierResolver
    {
        return new UserIdentifierResolver();
    }


    protected function entry(string $statusListId = self::LIST_ID, int $status = 0): StatusListEntryRecord
    {
        return new StatusListEntryRecord(
            $statusListId,
            7,
            true,
            $status,
            null,
            self::CREDENTIAL_ID,
            self::CREDENTIAL_ID_HASH,
            'UniversityDegree',
            self::SUBJECT_REF,
            null,
            null,
        );
    }


    protected function statusListRecord(int ...$allowedStatuses): MockObject
    {
        $statusList = $this->createMock(StatusListRecord::class);
        $statusList->method('isStatusValueAllowed')->willReturnCallback(
            static fn(int $status): bool => in_array($status, $allowedStatuses, true),
        );

        return $statusList;
    }


    /**
     * Enforced where a method added later is covered by existing rather than by being remembered.
     *
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function testRequiresAdminBeforeAnythingElse(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdmin')->with(true);

        $this->assertInstanceOf(CredentialStatusController::class, $this->sut());
    }


    /**
     * @throws \Throwable
     */
    public function testListsEntries(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findAllocatedPaginated')->willReturn(
            ['items' => [$this->entry()], 'total' => 1, 'numPages' => 1, 'currentPage' => 1],
        );
        $this->statusListEntryRepositoryMock->method('countNeverRetiringLists')->willReturn(3);
        $this->statusListEntryRepositoryMock->method('countLaneMismatches')->willReturn(2);
        $this->statusListRepositoryMock->method('findById')->willReturn($this->statusListRecord(0, 1));

        $this->sut()->index(new Request());

        $this->assertCount(1, $this->templateData['entries']);
        $this->assertSame(1, $this->templateData['total']);
        $this->assertSame(3, $this->templateData['neverRetiringListCount']);
        // Two distinct figures. The first is the expected cost of credentials issued without a
        // lifetime; the second should always be zero and means a list is holding a credential of a kind
        // its expiry lane says it cannot.
        $this->assertSame(2, $this->templateData['laneMismatchCount']);
        $this->assertSame('', $this->templateData['query']);
    }


    /**
     * An administrator has either a credential identifier or the identifier of the person it was
     * issued to, and cannot be expected to tell the interface which of the two they typed.
     *
     * @throws \Throwable
     */
    public function testSearchesForBothStoredFormsOfWhatWasTyped(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('hashCredentialId')->willReturn(self::CREDENTIAL_ID_HASH);
        $this->statusListEntryRepositoryMock->expects($this->once())
            ->method('findAllocatedPaginated')
            ->with(1, self::CREDENTIAL_ID_HASH, self::SUBJECT_REF)
            ->willReturn(['items' => [], 'total' => 0, 'numPages' => 1, 'currentPage' => 1]);

        $this->sut()->index(new Request(['q' => ' someone@example.org ']));

        $this->assertSame('someone@example.org', $this->templateData['query']);
    }


    /**
     * @throws \Throwable
     */
    public function testDoesNotSearchWithoutATerm(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->expects($this->never())->method('hashCredentialId');
        $this->subjectRefHasherMock->expects($this->never())->method('hash');
        $this->statusListEntryRepositoryMock->expects($this->once())
            ->method('findAllocatedPaginated')
            ->with(1, null, null)
            ->willReturn(['items' => [], 'total' => 0, 'numPages' => 1, 'currentPage' => 1]);

        $this->sut()->index(new Request());
    }


    /**
     * How many bits an entry occupies is fixed when its list is created, so offering a status the list
     * can never carry would put a button on the page whose only possible outcome is an error.
     *
     * @throws \Throwable
     */
    public function testOffersOnlyStatusesTheListCanCarry(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findAllocatedPaginated')->willReturn(
            ['items' => [$this->entry()], 'total' => 1, 'numPages' => 1, 'currentPage' => 1],
        );
        $this->statusListRepositoryMock->method('findById')->willReturn(
            $this->statusListRecord(StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value),
        );

        $this->sut()->index(new Request());

        $this->assertSame(
            [StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value],
            array_keys($this->templateData['allowedStatuses'][self::LIST_ID]),
        );
    }


    /**
     * Between showing an administrator no way to withdraw a credential and showing one which reports
     * why it did not work, the second is the one which can be acted on.
     *
     * @throws \Throwable
     */
    public function testOffersEveryStatusWhenTheListCannotBeRead(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findAllocatedPaginated')->willReturn(
            ['items' => [$this->entry()], 'total' => 1, 'numPages' => 1, 'currentPage' => 1],
        );
        $this->statusListRepositoryMock->method('findById')->willReturn(null);

        $this->sut()->index(new Request());

        $this->assertCount(
            count(StatusTypeEnum::cases()),
            $this->templateData['allowedStatuses'][self::LIST_ID],
        );
    }


    /**
     * @throws \Throwable
     */
    public function testLooksUpEachListOnlyOnce(): void
    {
        $this->statusListEntryRepositoryMock = $this->createMock(StatusListEntryRepository::class);
        $this->statusListEntryRepositoryMock->method('findAllocatedPaginated')->willReturn(
            [
                'items' => [$this->entry(), $this->entry(), $this->entry('another-list')],
                'total' => 3,
                'numPages' => 1,
                'currentPage' => 1,
            ],
        );
        $this->statusListRepositoryMock->expects($this->exactly(2))
            ->method('findById')
            ->willReturn($this->statusListRecord(0, 1));

        $this->sut()->index(new Request());
    }


    /**
     * @throws \Throwable
     */
    public function testAppliesTheRequestedStatus(): void
    {
        $this->credentialStatusServiceMock->expects($this->once())
            ->method('setStatus')
            ->with(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Admin, 'admin')
            ->willReturn(new CredentialStatusChange(self::LIST_ID, 7, 0, StatusTypeEnum::Invalid, true));

        $this->assertInstanceOf(RedirectResponse::class, $this->sut()->change(new Request()));
        $this->assertSame(['The credential status has been changed.'], $this->messages);
    }


    /**
     * Repeating a request is how somebody who never saw an answer recovers, so it is reported as
     * having already been done rather than as having been done again.
     *
     * @throws \Throwable
     */
    public function testReportsAStatusWhichWasAlreadyHeld(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(
            new CredentialStatusChange(
                self::LIST_ID,
                7,
                StatusTypeEnum::Invalid->value,
                StatusTypeEnum::Invalid,
                false,
            ),
        );

        $this->sut()->change(new Request());

        $this->assertSame(
            ['The credential already had that status, so nothing was changed.'],
            $this->messages,
        );
    }


    /**
     * @throws \Throwable
     */
    public function testReportsNothingWhichCanBeActedOn(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(null);

        $this->sut()->change(new Request());

        $this->assertStringContainsString('No credential', $this->messages[0]);
    }


    /**
     * @throws \Throwable
     */
    public function testReportsAStatusTheListCannotCarry(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new UnsupportedStatusException('Two bits are needed.'));

        $this->sut()->change(new Request());

        $this->assertStringContainsString('without room for that status', $this->messages[0]);
    }


    /**
     * @throws \Throwable
     */
    public function testReportsAChangeLostToAConcurrentOne(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new StatusConflictException('Somebody else got there first.'));

        $this->sut()->change(new Request());

        $this->assertStringContainsString('changed by something else at the same time', $this->messages[0]);
    }


    /**
     * @throws \Throwable
     */
    public function testReportsAFailureWithoutRepeatingItsDetail(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')
            ->willThrowException(new StatusListException('The database is on fire.'));

        $this->sut()->change(new Request());

        $this->assertSame(['The credential status could not be changed.'], $this->messages);
        $this->assertStringNotContainsString('on fire', $this->messages[0]);
    }


    /**
     * A stale or missing CSRF token lands here, and nothing is asked of the service.
     *
     * @throws \Throwable
     */
    public function testChangesNothingWhenTheFormIsNotAccepted(): void
    {
        $this->formMock = $this->createMock(CredentialStatusForm::class);
        $this->formMock->method('isSuccess')->willReturn(false);
        $this->formMock->method('getErrors')->willReturn(['Security token has expired.']);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->formFactoryMock->method('build')->willReturn($this->formMock);

        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->sut()->change(new Request());

        $this->assertSame(['The credential status change was not accepted. Please try again.'], $this->messages);
    }


    /**
     * @throws \Throwable
     */
    public function testChangesNothingWithoutACredentialIdentifier(): void
    {
        $this->formMock = $this->createMock(CredentialStatusForm::class);
        $this->formMock->method('isSuccess')->willReturn(true);
        $this->formMock->method('getValues')->willReturn([
            CredentialStatusForm::FIELD_CREDENTIAL_ID => '   ',
            CredentialStatusForm::FIELD_STATUS => StatusTypeEnum::Invalid->value,
        ]);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->formFactoryMock->method('build')->willReturn($this->formMock);

        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->sut()->change(new Request());

        $this->assertSame(['The credential status change was not accepted. Please try again.'], $this->messages);
    }


    /**
     * @throws \Throwable
     */
    public function testChangesNothingForAStatusWhichIsNotOne(): void
    {
        $this->formMock = $this->createMock(CredentialStatusForm::class);
        $this->formMock->method('isSuccess')->willReturn(true);
        $this->formMock->method('getValues')->willReturn([
            CredentialStatusForm::FIELD_CREDENTIAL_ID => self::CREDENTIAL_ID,
            CredentialStatusForm::FIELD_STATUS => 99,
        ]);
        $this->formFactoryMock = $this->createMock(FormFactory::class);
        $this->formFactoryMock->method('build')->willReturn($this->formMock);

        $this->credentialStatusServiceMock->expects($this->never())->method('setStatus');

        $this->sut()->change(new Request());

        $this->assertSame(['The credential status change was not accepted. Please try again.'], $this->messages);
    }


    /**
     * SimpleSAMLphp's administrator authentication is a shared password in most deployments, which
     * names nobody. Where it has been pointed at a real authentication source, the identifier it
     * releases is a genuine answer to who did this.
     *
     * @throws \Throwable
     */
    public function testRecordsTheAdministratorWhenTheLoginKnowsWhoTheyAre(): void
    {
        $this->authSimpleMock = $this->createMock(Simple::class);
        $this->authSimpleMock->method('isAuthenticated')->willReturn(true);
        $this->authSimpleMock->method('getAttributes')->willReturn(['uid' => ['jane.doe']]);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactoryMock->method('forAuthSourceId')->willReturn($this->authSimpleMock);

        $this->credentialStatusServiceMock->expects($this->once())
            ->method('setStatus')
            ->with(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Admin, 'jane.doe')
            ->willReturn(new CredentialStatusChange(self::LIST_ID, 7, 0, StatusTypeEnum::Invalid, true));

        $this->sut()->change(new Request());
    }


    /**
     * A credential must not stay in a wallet because the administrator behind the request could not
     * be named.
     *
     * @throws \Throwable
     */
    public function testStillChangesTheStatusWhenTheAdministratorCannotBeIdentified(): void
    {
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authSimpleFactoryMock->method('forAuthSourceId')
            ->willThrowException(new RuntimeException('No such authentication source.'));

        $this->credentialStatusServiceMock->expects($this->once())
            ->method('setStatus')
            ->with(self::CREDENTIAL_ID, StatusTypeEnum::Invalid, StatusChangeSourceEnum::Admin, 'admin')
            ->willReturn(new CredentialStatusChange(self::LIST_ID, 7, 0, StatusTypeEnum::Invalid, true));

        $this->sut()->change(new Request());
    }


    /**
     * @throws \Throwable
     */
    public function testReturnsToThePageTheChangeWasMadeFrom(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(
            new CredentialStatusChange(self::LIST_ID, 7, 0, StatusTypeEnum::Invalid, true),
        );

        $this->routesMock->expects($this->once())
            ->method('newRedirectResponseToModuleUrl')
            ->with('admin/credential-status', ['q' => 'someone@example.org', 'page' => 3])
            ->willReturn(new RedirectResponse('https://op.example.org/back'));

        $this->sut()->change(new Request([], ['q' => 'someone@example.org', 'page' => '3']));
    }


    /**
     * @throws \Throwable
     */
    public function testDoesNotCarryAnEmptySearchOrTheFirstPageBack(): void
    {
        $this->credentialStatusServiceMock->method('setStatus')->willReturn(
            new CredentialStatusChange(self::LIST_ID, 7, 0, StatusTypeEnum::Invalid, true),
        );

        $this->routesMock->expects($this->once())
            ->method('newRedirectResponseToModuleUrl')
            ->with('admin/credential-status', [])
            ->willReturn(new RedirectResponse('https://op.example.org/back'));

        $this->sut()->change(new Request([], ['q' => '', 'page' => '1']));
    }
}
