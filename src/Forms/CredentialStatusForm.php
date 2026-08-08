<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Forms;

use Nette\Forms\Form;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

/**
 * Asks for one issued credential to be moved to one status.
 *
 * The listing renders a copy of this per row, so the markup is written out in the template rather than
 * by this class: each row offers only the statuses the list that credential sits in can actually hold,
 * which is fixed when the list is created and differs from row to row. What this class is for is the
 * other direction -- validating what comes back, and carrying the CSRF protection.
 *
 * Every status is offered here even though a given row shows fewer, because this decides only whether a
 * submitted value is a status at all. Whether that status is one the credential's list can carry is not
 * this form's to answer: it depends on the row, and it is enforced where it can not be bypassed, below
 * the service which applies the change.
 *
 * @psalm-suppress PropertyNotSetInConstructor Raised for $httpRequest which is marked as internal.
 * @see \SimpleSAML\Test\Module\oidc\unit\Forms\CredentialStatusFormTest
 */
class CredentialStatusForm extends Form
{
    final public const string FIELD_CREDENTIAL_ID = 'credential_id';

    final public const string FIELD_STATUS = 'status';

    /**
     * @throws \Exception
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected CsrfProtection $csrfProtection,
        protected SspBridge $sspBridge,
        protected Helpers $helpers,
    ) {
        parent::__construct();

        $this->buildForm();
    }

    /**
     * The statuses this form accepts, as submitted value to label.
     *
     * @return array<int,string>
     */
    public static function statusOptions(): array
    {
        $options = [];

        foreach (StatusTypeEnum::cases() as $status) {
            $options[$status->value] = self::labelFor($status);
        }

        return $options;
    }

    /**
     * Wording an administrator can act on, rather than the specification's own terms.
     *
     * "Invalid" in particular is what the specification calls a status which every other document in
     * this space calls revoked, and an administrator looking for the way to withdraw a credential
     * should not have to know that.
     */
    public static function labelFor(StatusTypeEnum $status): string
    {
        return match ($status) {
            StatusTypeEnum::Valid => Translate::noop('Valid'),
            StatusTypeEnum::Invalid => Translate::noop('Revoked'),
            StatusTypeEnum::Suspended => Translate::noop('Suspended'),
        };
    }

    /**
     * @throws \Exception
     */
    protected function buildForm(): void
    {
        $this->setMethod('POST');
        $this->addComponent($this->csrfProtection, Form::ProtectorId);

        $this->addHidden(self::FIELD_CREDENTIAL_ID)
            ->setRequired(Translate::noop('Credential identifier is missing.'));

        $this->addSelect(self::FIELD_STATUS, Translate::noop('Status'), self::statusOptions())
            ->setRequired(Translate::noop('Status to set is missing.'));
    }
}
