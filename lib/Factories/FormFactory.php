<?php

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
use SimpleSAML\Module\oidc\Services\ConfigurationService;

class FormFactory
{
    /**
     * @var \SimpleSAML\Module\oidc\Services\ConfigurationService
     */
    private $configurationService;

    public function __construct(ConfigurationService $configurationService)
    {
        $this->configurationService = $configurationService;
    }

    /**
     * @param string $classname Form classname
     *
     * @throws \Exception
     *
     * @return mixed
     */
    public function build(string $classname)
    {
        if (!class_exists($classname) && ($classname instanceof Form)) {
            throw new Exception("Invalid form: {$classname}");
        }

        /** @psalm-suppress InvalidStringClass */
        return new $classname($this->configurationService);
    }
}
