<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Forms\Controls;

use Nette\Forms\Controls\TextInput;
use Nette\Forms\Form;

/**
 * A single-line text input which keeps the value as it was submitted. Nette's TextInput trims what it loads from the
 * request (Form::DataLine), which cuts a significant space off a value: the escaped one RFC 4514 lets a
 * distinguished name end with ("CN=Provider\\ "), for one.
 */
class UntrimmedTextInput extends TextInput
{
    public function loadHttpData(): void
    {
        // As Nette's TextInput::loadHttpData() sets it, with the data type which keeps the value whole.
        /** @psalm-suppress InternalMethod */
        $this->setValue($this->getHttpData(Form::DataText));
    }
}
