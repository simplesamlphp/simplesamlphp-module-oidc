<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use SimpleSAML\XHTML\Template;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;
use SimpleSAML\Configuration;

class FormPostResponseMode implements ResponseModeInterface
{
    private Configuration $simpleSAMLConfiguration;

    public function __construct(
        Configuration $simpleSAMLConfiguration,
    ) {
        $this->simpleSAMLConfiguration = $simpleSAMLConfiguration;
    }

    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        $template = new Template($this->simpleSAMLConfiguration, 'oidc:formpost.twig');
        $template->data = [
            'redirectUri' => $redirectUri,
            'params'      => $params,
        ];
        $html = $template->getContents();   // renders to a string

        $response = new HtmlResponse();
        $response->setHtml($html);
        return $response;
    }
}