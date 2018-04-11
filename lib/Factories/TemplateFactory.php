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
    /**
     * @var \SimpleSAML_Configuration
     */
    private $configuration;

    public function __construct(\SimpleSAML_Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    public function render(string $templateName, array $data = []): \SimpleSAML_XHTML_Template
    {
        $template = new \SimpleSAML_XHTML_Template($this->configuration, $templateName);
        $template->data += $data;

        return $template;
    }
}
