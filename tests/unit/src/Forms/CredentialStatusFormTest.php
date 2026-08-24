<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Forms;

use Nette\Forms\Controls\SelectBox;
use Nette\Forms\Form;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Forms\CredentialStatusForm;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Codebooks\StatusTypeEnum;

#[CoversClass(CredentialStatusForm::class)]
#[AllowMockObjectsWithoutExpectations]
class CredentialStatusFormTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $csrfProtectionMock;

    protected MockObject $sspBridgeMock;

    protected Helpers $helpers;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->csrfProtectionMock = $this->createMock(CsrfProtection::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->helpers = new Helpers();
    }


    /**
     * @throws \Exception
     */
    protected function sut(): CredentialStatusForm
    {
        return new CredentialStatusForm(
            $this->moduleConfigMock,
            $this->csrfProtectionMock,
            $this->sspBridgeMock,
            $this->helpers,
        );
    }


    /**
     * @throws \Exception
     */
    public function testCarriesTheFieldsTheListingSubmits(): void
    {
        $form = $this->sut();

        $this->assertNotNull($form->getComponent(CredentialStatusForm::FIELD_CREDENTIAL_ID));
        $this->assertNotNull($form->getComponent(CredentialStatusForm::FIELD_STATUS));
    }


    /**
     * CSRF protection is why this class exists at all: the markup is written out in the template, and
     * validating what comes back is what is left.
     *
     * @throws \Exception
     */
    public function testAttachesTheCsrfProtector(): void
    {
        $this->assertSame($this->csrfProtectionMock, $this->sut()->getComponent(Form::ProtectorId));
    }


    /**
     * @throws \Exception
     */
    public function testIsSubmittedByPost(): void
    {
        $this->assertSame(Form::Post, $this->sut()->getMethod());
    }


    /**
     * The listing shows fewer options per row, since a list can be unable to carry a status. This
     * decides only whether what came back is a status at all.
     *
     * @throws \Exception
     */
    public function testAcceptsEveryStatus(): void
    {
        $status = $this->sut()->getComponent(CredentialStatusForm::FIELD_STATUS);

        $this->assertInstanceOf(SelectBox::class, $status);
        $this->assertSame(
            [StatusTypeEnum::Valid->value, StatusTypeEnum::Invalid->value, StatusTypeEnum::Suspended->value],
            array_keys($status->getItems()),
        );
    }


    /**
     * The submitted value has to come back as the Status Type's own backing value, since that is what
     * the controller turns back into a Status Type.
     *
     * @throws \Exception
     */
    public function testKeepsStatusValuesAsIntegers(): void
    {
        $form = $this->sut();
        $status = $form->getComponent(CredentialStatusForm::FIELD_STATUS);
        $this->assertInstanceOf(SelectBox::class, $status);

        $status->setValue(StatusTypeEnum::Suspended->value);

        $this->assertSame(StatusTypeEnum::Suspended->value, $status->getValue());
    }


    /**
     * "Invalid" is what the specification calls a status which every other document in this space
     * calls revoked, and an administrator should not have to know that to withdraw a credential.
     */
    public function testLabelsTheInvalidStatusAsRevoked(): void
    {
        $this->assertSame('Revoked', CredentialStatusForm::labelFor(StatusTypeEnum::Invalid));
        $this->assertSame('Valid', CredentialStatusForm::labelFor(StatusTypeEnum::Valid));
        $this->assertSame('Suspended', CredentialStatusForm::labelFor(StatusTypeEnum::Suspended));
    }


    public function testOffersOneOptionPerStatus(): void
    {
        $this->assertCount(count(StatusTypeEnum::cases()), CredentialStatusForm::statusOptions());
    }
}
