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

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use Nette\Forms\Form;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;

class FormFactory
{
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    public function __construct(ConfigurationService $configurationService)
    {
        $this->configurationService = $configurationService;
    }

    /**
     * @param string $name Form name
     *
     * @throws \SimpleSAML_Error_Exception
     *
     * @return mixed
     */
    public function build(string $classname)
    {
        if (!class_exists($classname)
            && $classname instanceof Form) {
            throw new \SimpleSAML_Error_Exception("Invalid form: {$classname}");
        }

        return new $classname($this->configurationService);
    }
}
