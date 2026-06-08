<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;

class FormPostResponseMode implements ResponseModeInterface
{
    private TemplateFactory $templateFactory;

    public function __construct(
        TemplateFactory $templateFactory,
    ) {
        $this->templateFactory = $templateFactory;
    }

    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        $template = $this->templateFactory->build(
            templateName: 'oidc:formpost.twig',
            data: [
                'redirectUri' => $redirectUri,
                'params'      => $params,
            ],
            showMenu: false,
            showModuleName: false,
            showSubPageTitle: false,
        );
        $html = $template->getContents();   // renders to a string

        $response = new HtmlResponse();
        $response->setHtml($html);
        return $response;
    }
}
