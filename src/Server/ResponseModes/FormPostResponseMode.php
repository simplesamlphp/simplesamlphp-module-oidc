<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseModes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Server\ResponseTypes\HtmlResponse;
use SimpleSAML\OpenID\Codebooks\ResponseModesEnum;

class FormPostResponseMode implements ResponseModeInterface
{
    public function __construct(private readonly TemplateFactory $templateFactory)
    {
    }


    public function buildResponse(string $redirectUri, array $params): AbstractResponseType
    {
        // A parameter without a value is left out, as http_build_query() leaves it out of the other two modes: the
        // template posts every parameter it is given, and a response carries `state` only when the request did (RFC
        // 6749 sections 4.1.2 and 4.2.2), not empty. Only null: a state of "0" is a value the client sent.
        $params = array_filter($params, static fn(mixed $value): bool => $value !== null);

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


    public function getMode(): ResponseModesEnum
    {
        return ResponseModesEnum::FormPost;
    }
}
