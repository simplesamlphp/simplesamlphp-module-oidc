<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use Nette\Forms\Form;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;

class FormFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly CsrfProtection $csrfProtection,
        protected readonly SspBridge $sspBridge,
        protected readonly Helpers $helpers,
    ) {
    }


    /**
     * @param class-string $classname Form classname
     *
     * @throws \SimpleSAML\Error\Exception
     */
    public function build(string $classname): Form
    {
        if (!is_a($classname, Form::class, true)) {
            throw new Exception("Invalid form: $classname");
        }

        /** @psalm-suppress UnsafeInstantiation */
        return new $classname(
            $this->moduleConfig,
            $this->csrfProtection,
            $this->sspBridge,
            $this->helpers,
        );
    }
}
