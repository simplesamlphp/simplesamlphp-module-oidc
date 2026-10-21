<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Forms\Controls;

use Nette\Forms\Form;
use Nette\Http\Request;
use Nette\Http\UrlScript;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidc\Forms\Controls\UntrimmedTextInput;

#[CoversClass(UntrimmedTextInput::class)]
class UntrimmedTextInputTest extends TestCase
{
    /**
     * As a browser submits it: the value as sent, where Nette's own text input trims it.
     */
    public function testLoadsTheSubmittedValueUntrimmed(): void
    {
        $form = new Form();
        $form->setMethod('POST');
        $form->httpRequest = new Request(
            new UrlScript('https://op.example.org/clients/edit'),
            post: ['identity' => 'O=Example,CN=Wallet Provider\\ ', 'trimmed' => ' https://wallet.example.org '],
            headers: ['Sec-Fetch-Site' => 'same-origin'],
            method: 'POST',
        );
        $form->addComponent(new UntrimmedTextInput('Identity'), 'identity');
        $form->addText('trimmed', 'Trimmed');

        $form['identity']->loadHttpData();
        $form['trimmed']->loadHttpData();

        $this->assertSame('O=Example,CN=Wallet Provider\\ ', $form['identity']->getValue());
        $this->assertSame('https://wallet.example.org', $form['trimmed']->getValue());
    }
}
