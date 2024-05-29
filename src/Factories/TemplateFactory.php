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

use SimpleSAML\Configuration;
use SimpleSAML\XHTML\Template;

class TemplateFactory
{
    private readonly Configuration $configuration;

    public function __construct(Configuration $configuration)
    {
        $this->configuration = new Configuration($configuration->toArray(), 'oidc');
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function render(string $templateName, array $data = []): Template
    {
        $template = new Template($this->configuration, $templateName);
        $template->data += $data;

        return $template;
    }
}
