<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Services;

use Nette\Forms\Form;

class FormFactory
{
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

        return new $classname();
    }
}
