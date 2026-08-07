<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Codebooks\StatusChangeSourceEnum;
use SimpleSAML\Module\oidc\Exceptions\StatusConflictException;
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
use SimpleSAML\Module\oidc\StatusList\Values\StatusListRecord;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\Module\oidc\Utils\UserIdentifierResolver;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Withdrawing, suspending and reinstating issued credentials from the administration screens.
 *
 * The counterpart to the credential status API endpoint, for the case where there is nothing on the
 * other end to call it: someone reports a lost phone, and an administrator has to act on that now.
 *
 * Authorization is enforced in the constructor rather than in each action, so that a method added later
 * is protected by existing rather than by being remembered. It is administrator only -- deliberately
 * not the client permission which the client registry accepts, since holding that says something about
 * one's own OpenID Connect clients and nothing about withdrawing credentials issued to other people.
 * The CSRF protection on the change action is in addition to that and not a substitute for it: it
 * establishes that the administrator meant to make this request, never that they are an administrator.
 *
 * @see \SimpleSAML\Test\Module\oidc\unit\Controllers\Admin\CredentialStatusControllerTest
 */
class CredentialStatusController
{
    final public const string PARAM_PAGE = 'page';

    final public const string PARAM_QUERY = 'q';

    /**
     * The authentication source SimpleSAMLphp's administrator login goes through, consulted only to
     * find out whether it knows who the administrator is.
     */
    protected const string ADMIN_AUTH_SOURCE_ID = 'admin';

    /**
     * Recorded as the actor when the administrator login has no individual behind it, which is the
     * usual case: SimpleSAMLphp's administrator authentication is a shared password by default.
     */
    protected const string ACTOR_REF_ADMIN = 'admin';

    /** Width of the column an actor reference is stored in. */
    protected const int ACTOR_REF_MAX_LENGTH = 191;

    /**
     * @throws \SimpleSAML\Module\oidc\Exceptions\AuthorizationException
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly StatusListEntryRepository $statusListEntryRepository,
        protected readonly StatusListRepository $statusListRepository,
        protected readonly CredentialStatusService $credentialStatusService,
        protected readonly SubjectRefHasher $subjectRefHasher,
        protected readonly FormFactory $formFactory,
        protected readonly SessionMessagesService $sessionMessagesService,
        protected readonly AuthSimpleFactory $authSimpleFactory,
        protected readonly UserIdentifierResolver $userIdentifierResolver,
        protected readonly Routes $routes,
        protected readonly LoggerService $logger,
    ) {
        $this->authorization->requireAdmin(true);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Error\Exception
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     * @throws \Exception
     */
    public function index(Request $request): Response
    {
        $query = trim($request->query->getString(self::PARAM_QUERY));

        // One box, matched against both stored forms of what was typed. An administrator has either a
        // credential identifier, taken from the credential itself, or the identifier of the person it
        // was issued to, and cannot be expected to tell the interface which of the two it is.
        $credentialIdHash = $query === '' ?
        null :
        $this->statusListEntryRepository->hashCredentialId($query);
        $subjectRef = $query === '' ? null : $this->subjectRefHasher->hash($query);

        $pagination = $this->statusListEntryRepository->findAllocatedPaginated(
            $request->query->getInt(self::PARAM_PAGE, 1),
            $credentialIdHash,
            $subjectRef,
        );

        return $this->templateFactory->build(
            'oidc:credential-status.twig',
            [
                'entries' => $pagination['items'],
                'total' => $pagination['total'],
                'numPages' => $pagination['numPages'],
                'currentPage' => $pagination['currentPage'],
                'query' => $query,
                'allowedStatuses' => $this->resolveAllowedStatuses($pagination['items']),
                'statusLabels' => CredentialStatusForm::statusOptions(),
                'neverRetiringListCount' => $this->statusListEntryRepository->countNeverRetiringLists(),
                'form' => $this->formFactory->build(CredentialStatusForm::class),
                'actionRoute' => $this->routes->urlAdminCredentialStatusChange(),
            ],
            RoutesEnum::AdminCredentialStatus->value,
        );
    }

    /**
     * @throws \SimpleSAML\Error\Exception
     */
    public function change(Request $request): Response
    {
        $form = $this->formFactory->build(CredentialStatusForm::class);

        if (!$form->isSuccess()) {
            // Everything this form validates is either present or the request did not come from the
            // listing: a missing or stale CSRF token, a status which is not a status. There is nothing
            // for the administrator to correct field by field, so the errors are not rendered back.
            $this->logger->warning(
                'CredentialStatusController: a credential status change was not accepted.',
                ['errors' => $form->getErrors()],
            );

            return $this->redirectToListing(
                $request,
                Translate::noop('The credential status change was not accepted. Please try again.'),
            );
        }

        $values = $form->getValues('array');
        $credentialId = is_string($values[CredentialStatusForm::FIELD_CREDENTIAL_ID] ?? null) ?
        trim((string)$values[CredentialStatusForm::FIELD_CREDENTIAL_ID]) :
        '';
        // Cast rather than matched, since the form has already established this is one of the values
        // offered; only its type is left open, the select carrying integer keys.
        $status = is_numeric($values[CredentialStatusForm::FIELD_STATUS] ?? null) ?
        StatusTypeEnum::tryFrom((int)$values[CredentialStatusForm::FIELD_STATUS]) :
        null;

        if ($credentialId === '' || !$status instanceof StatusTypeEnum) {
            return $this->redirectToListing(
                $request,
                Translate::noop('The credential status change was not accepted. Please try again.'),
            );
        }

        return $this->redirectToListing($request, $this->applyStatus($credentialId, $status));
    }

    /**
     * @return string What to tell the administrator, which is the only answer this surface gives: the
     * listing it returns to shows the outcome regardless.
     */
    protected function applyStatus(string $credentialId, StatusTypeEnum $status): string
    {
        try {
            $change = $this->credentialStatusService->setStatus(
                $credentialId,
                $status,
                StatusChangeSourceEnum::Admin,
                $this->resolveActorRef(),
            );
        } catch (UnsupportedStatusException $exception) {
            // Fixed when the list was created and not something retrying can change, so this says what
            // would have to be different rather than inviting another attempt.
            $this->logger->error(
                'CredentialStatusController: requested status can not be represented: ' . $exception->getMessage(),
            );

            return Translate::noop(
                'This credential belongs to a Status List which was created without room for that ' .
                'status. Credentials issued from now on can carry it once the pool is configured for ' .
                'it, but the ones already in this list can not.',
            );
        } catch (StatusConflictException $exception) {
            $this->logger->error(
                'CredentialStatusController: status change lost to concurrent changes: ' . $exception->getMessage(),
            );

            return Translate::noop(
                'The status of this credential was changed by something else at the same time, so it ' .
                'now holds something other than what was asked for. Check what it says and try again.',
            );
        } catch (Throwable $exception) {
            $this->logger->error(
                'CredentialStatusController: unable to change the credential status: ' . $exception->getMessage(),
            );

            return Translate::noop('The credential status could not be changed.');
        }

        if (!$change instanceof CredentialStatusChange) {
            return Translate::noop(
                'No credential which can have its status changed was found. It may have expired, in ' .
                'which case it is already refused on its own claims.',
            );
        }

        return $change->isChanged() ?
        Translate::noop('The credential status has been changed.') :
        Translate::noop('The credential already had that status, so nothing was changed.');
    }

    /**
     * Who to record as having asked for a change.
     *
     * SimpleSAMLphp's administrator authentication is a shared password in most deployments, which
     * names nobody, and a trail claiming otherwise would be worse than one which does not. Where a
     * deployment has pointed that login at a real authentication source instead, the identifier it
     * releases is a genuine answer to who did this, and is recorded.
     *
     * Never allowed to fail: this is a label on an audit row, and a credential must not stay in a
     * wallet because its administrator could not be named.
     */
    protected function resolveActorRef(): string
    {
        try {
            $adminAuth = $this->authSimpleFactory->forAuthSourceId(self::ADMIN_AUTH_SOURCE_ID);

            if ($adminAuth->isAuthenticated()) {
                $userId = $this->userIdentifierResolver->resolve(
                    $this->moduleConfig->getUserIdentifierAttributes(),
                    $adminAuth->getAttributes(),
                );

                if (is_string($userId) && $userId !== '') {
                    return mb_substr($userId, 0, self::ACTOR_REF_MAX_LENGTH);
                }
            }
        } catch (Throwable $throwable) {
            $this->logger->debug(
                'CredentialStatusController: could not resolve the administrator identity: ' .
                $throwable->getMessage(),
            );
        }

        return self::ACTOR_REF_ADMIN;
    }

    /**
     * Which statuses each listed credential can actually be moved to, keyed by the list it sits in.
     *
     * How many bits an entry occupies is fixed when its list is created, so a list can be unable to
     * carry a status permanently. Offering one anyway would put a button on the page whose only
     * possible outcome is an error message.
     *
     * @param \SimpleSAML\Module\oidc\StatusList\Values\StatusListEntryRecord[] $entries
     * @return array<string,array<int,string>> List ID to status value to label.
     * @throws \SimpleSAML\Module\oidc\Exceptions\StatusListException
     */
    protected function resolveAllowedStatuses(array $entries): array
    {
        $allowed = [];

        foreach ($entries as $entry) {
            $statusListId = $entry->getStatusListId();

            if (array_key_exists($statusListId, $allowed)) {
                continue;
            }

            $statusList = $this->statusListRepository->findById($statusListId);
            $options = [];

            foreach (StatusTypeEnum::cases() as $status) {
                // A list which cannot be read at all is offered everything rather than nothing. The
                // foreign key makes its absence a broken database rather than a state to design for,
                // and between showing an administrator no way to withdraw a credential and showing one
                // which reports why it did not work, the second is the one that can be acted on.
                if (!$statusList instanceof StatusListRecord || $statusList->isStatusValueAllowed($status->value)) {
                    $options[$status->value] = CredentialStatusForm::labelFor($status);
                }
            }

            $allowed[$statusListId] = $options;
        }

        return $allowed;
    }

    /**
     * Back to the listing the change was made from, on the page and search it was made from.
     */
    protected function redirectToListing(Request $request, string $message): Response
    {
        $this->sessionMessagesService->addMessage($message);

        $parameters = [];
        $query = trim($request->request->getString(self::PARAM_QUERY));
        $page = $request->request->getInt(self::PARAM_PAGE, 1);

        if ($query !== '') {
            $parameters[self::PARAM_QUERY] = $query;
        }

        if ($page > 1) {
            $parameters[self::PARAM_PAGE] = $page;
        }

        return $this->routes->newRedirectResponseToModuleUrl(
            RoutesEnum::AdminCredentialStatus->value,
            $parameters,
        );
    }
}
