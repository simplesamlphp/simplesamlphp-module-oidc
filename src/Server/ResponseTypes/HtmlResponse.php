<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes;

use League\OAuth2\Server\ResponseTypes\AbstractResponseType;
use Psr\Http\Message\ResponseInterface;

class HtmlResponse extends AbstractResponseType
{
    private string $html = '';

    public function setHtml(string $html): void
    {
        $this->html = $html;
    }

    public function generateHttpResponse(ResponseInterface $response): ResponseInterface
    {
        $response->getBody()->write($this->html);

        return $response->withStatus(200)->withHeader('Content-Type', 'text/html');
    }
}
