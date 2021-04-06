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

namespace SimpleSAML\Modules\OpenIDConnect\Form\Controls;

use Nette\Forms\Controls\CsrfProtection as BaseCsrfProtection;
use Nette\Utils\Random;
use SimpleSAML\Session;

class CsrfProtection extends BaseCsrfProtection
{
    public const PROTECTION = 'SimpleSAML\Modules\OpenIDConnect\Form\Controls\CsrfProtection::validateCsrf';

    public function __construct($errorMessage)
    {
        parent::__construct($errorMessage);

        $this->getRules()->reset();
        $this->addRule(self::PROTECTION, $errorMessage);
    }

    public function getToken(): string
    {
        /** @var Session $session */
        $session = Session::getSession();
        $token = $session->getData('form_csrf', 'token');

        if (!$token) {
            $token = Random::generate();
            $session->setData('form_csrf', 'token', $token);
        }

        return $token ^ $session->getSessionId();
    }
}
