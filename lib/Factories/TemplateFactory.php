<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

class TemplateFactory
{
    private $config;

    public function __construct()
    {
        $this->config = \SimpleSAML_Configuration::getInstance();
    }

    public function render(string $templateName, array $data = []): \SimpleSAML_XHTML_Template
    {
        $template = new \SimpleSAML_XHTML_Template($this->config, $templateName);
        $template->data += $data;

        return $template;
    }
}
