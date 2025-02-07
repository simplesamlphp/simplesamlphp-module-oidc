<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Factories;

use Nette\Forms\Form;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Forms\Controls\CsrfProtection;
use SimpleSAML\Module\oidc\ModuleConfig;

class FormFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly CsrfProtection $csrfProtection,
        protected readonly SspBridge $sspBridge,
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
        );
    }
}
