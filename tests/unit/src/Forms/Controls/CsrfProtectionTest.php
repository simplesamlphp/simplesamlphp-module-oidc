<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Forms\Controls;

use Nette\Forms\Controls\CsrfProtection as NetteCsrfProtection;
use Nette\Forms\Form;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Session;

/**
 * Nette's CSRF control with SimpleSAMLphp's session in place of Nette's.
 *
 * Nette's control keeps its token in a Nette session which it starts itself the moment the control is
 * attached to a form. The module's constructor goes past that class's constructor to the hidden field's,
 * so no Nette session is ever set up, and the token lives in the SimpleSAMLphp session instead, under
 * `form_csrf`/`token`. Everything else is Nette's: the field is omitted from the form's values, required,
 * and validated by `validateCsrf`, which reads the token back through the overridden `getToken()`. The
 * token handed out is the stored one masked with the session ID, as Nette does, so a form filled in one
 * session does not validate in another.
 *
 * One statement stays uncovered: the constructor's guard against `get_parent_class()` answering false,
 * which it cannot for a class two levels below the hidden field.
 */
#[CoversClass(CsrfProtection::class)]
#[AllowMockObjectsWithoutExpectations]
class CsrfProtectionTest extends TestCase
{
    protected const string ERROR_MESSAGE = 'The form has expired, please submit it again.';

    protected const string SESSION_ID = 'k9f2h7d1c4b8a6e3f5g0j2m4n6p8q1r3';

    /**
     * Ten characters of `0-9a-z`, as `Nette\Utils\Random::generate()` mints one.
     */
    protected const string TOKEN = 'x7k2m9q4wz';


    protected MockObject $sessionMock;


    protected function setUp(): void
    {
        $this->sessionMock = $this->createMock(Session::class);
        $this->sessionMock->method('getSessionId')->willReturn(self::SESSION_ID);
    }


    protected function sut(?string $errorMessage = self::ERROR_MESSAGE): CsrfProtection
    {
        return new CsrfProtection($errorMessage, $this->sessionMock);
    }


    public function testCanCreateInstance(): void
    {
        $control = $this->sut();

        $this->assertInstanceOf(CsrfProtection::class, $control);
        $this->assertInstanceOf(NetteCsrfProtection::class, $control);
    }


    /**
     * The hidden field's constructor ran, so the control is a hidden input; the module's constructor then
     * set it up as Nette's does, minus the session: omitted from the form's values, required, and with the
     * module's `validateCsrf` rule carrying the given message.
     */
    public function testIsAnOmittedRequiredHiddenFieldValidatedByTheModulesRule(): void
    {
        $control = $this->sut();

        $this->assertSame('hidden', $control->getOption('type'));
        $this->assertTrue($control->isOmitted());
        $this->assertTrue($control->isRequired());

        $rules = [];
        foreach ($control->getRules() as $rule) {
            $rules[] = [$rule->validator, $rule->message];
        }

        $this->assertSame(
            [
                [Form::Filled, null],
                [[CsrfProtection::class, 'validateCsrf'], self::ERROR_MESSAGE],
            ],
            $rules,
        );
    }


    /**
     * Nette's constructor arranges for a Nette session to be started when the control joins a form. The
     * module's constructor is there to skip that, so joining a form leaves the control without one -- the
     * SimpleSAMLphp session is the one it uses.
     */
    public function testJoiningAFormStartsNoNetteSession(): void
    {
        $control = $this->sut();

        (new Form())->addComponent($control, Form::ProtectorId);

        $this->assertNull($control->session);
    }


    /**
     * Masked with the session ID, as Nette does, so the same stored token is another token in another
     * session and a form filled in one session does not validate in the other.
     *
     * @throws \Exception
     */
    public function testTheTokenIsTheStoredOneMaskedWithTheSessionId(): void
    {
        $this->sessionMock->expects($this->once())
            ->method('getData')
            ->with('form_csrf', 'token')
            ->willReturn(self::TOKEN);
        $this->sessionMock->expects($this->never())->method('setData');

        $token = $this->sut()->getToken();

        $this->assertSame(self::TOKEN ^ self::SESSION_ID, $token);
        $this->assertNotSame(self::TOKEN, $token);
    }


    /**
     * With no token stored yet one is minted, ten characters of `0-9a-z`, stored under `form_csrf`/`token`,
     * and handed out masked like a stored one would be.
     *
     * @throws \Exception
     */
    #[DataProvider('noStoredTokenProvider')]
    public function testMintsAndStoresATokenWhenThereIsNone(mixed $stored): void
    {
        $this->sessionMock->method('getData')->with('form_csrf', 'token')->willReturn($stored);
        $minted = null;
        $this->sessionMock->expects($this->once())
            ->method('setData')
            ->with('form_csrf', 'token', $this->matchesRegularExpression('/^[0-9a-z]{10}$/'))
            ->willReturnCallback(static function (string $type, string $id, mixed $data) use (&$minted): void {
                $minted = $data;
            });

        $token = $this->sut()->getToken();

        $this->assertIsString($minted);
        $this->assertSame($minted ^ self::SESSION_ID, $token);
    }


    /**
     * @return array<string,array{mixed}>
     */
    public static function noStoredTokenProvider(): array
    {
        return [
            'nothing stored' => [null],
            'an empty string stored' => [''],
        ];
    }
}
