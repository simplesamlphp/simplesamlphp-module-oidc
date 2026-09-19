<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use PHPMailer\PHPMailer\PHPMailer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\EmailFactory;
use SimpleSAML\Utils\EMail;

/**
 * The factory behind the transaction code email.
 *
 * CredentialOfferUriFactory builds the email carrying a transaction code through it, with a subject and the
 * recipient; nothing else calls it. The factory's whole job is to hand SimpleSAMLphp's EMail the subject, the
 * sender and recipient, and the two templates, which default to SimpleSAMLphp's own. EMail keeps the mailer
 * and the template names to itself, so the tests read them back by reflection: the mailer is PHPMailer, whose
 * subject, sender and recipients are public.
 *
 * The sender and recipient are always given here. EMail resolves a missing one from the SimpleSAMLphp
 * configuration, and the test configuration leaves `technicalcontact_email` at the default EMail refuses,
 * so what a missing one becomes is EMail's to test, not this factory's.
 */
#[CoversClass(EmailFactory::class)]
class EmailFactoryTest extends TestCase
{
    protected const string SUBJECT = 'Your one-time code';

    protected const string FROM = 'issuer@example.org';

    protected const string TO = 'holder@example.org';


    protected function sut(): EmailFactory
    {
        return new EmailFactory();
    }


    protected function propertyOf(EMail $email, string $property): mixed
    {
        return (new ReflectionProperty($email, $property))->getValue($email);
    }


    protected function mailerOf(EMail $email): PHPMailer
    {
        $mailer = $this->propertyOf($email, 'mail');
        $this->assertInstanceOf(PHPMailer::class, $mailer);

        return $mailer;
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(EmailFactory::class, $this->sut());
    }


    /**
     * The subject, sender and recipient are on the mailer as given, the recipient with no name.
     */
    public function testBuildsTheEmailWithTheSubjectSenderAndRecipient(): void
    {
        $email = $this->sut()->build(self::SUBJECT, self::FROM, self::TO);

        $mailer = $this->mailerOf($email);
        $this->assertSame(self::SUBJECT, $mailer->Subject);
        $this->assertSame(self::FROM, $mailer->From);
        $this->assertSame([[self::TO, '']], $mailer->getToAddresses());
    }


    public function testDefaultsToSimpleSamlPhpsOwnTemplates(): void
    {
        $email = $this->sut()->build(self::SUBJECT, self::FROM, self::TO);

        $this->assertSame('mailtxt.twig', $this->propertyOf($email, 'txt_template'));
        $this->assertSame('mailhtml.twig', $this->propertyOf($email, 'html_template'));
    }


    public function testHandsOverTheTemplatesItIsGiven(): void
    {
        $email = $this->sut()->build(self::SUBJECT, self::FROM, self::TO, 'code.txt.twig', 'code.html.twig');

        $this->assertSame('code.txt.twig', $this->propertyOf($email, 'txt_template'));
        $this->assertSame('code.html.twig', $this->propertyOf($email, 'html_template'));
    }
}
