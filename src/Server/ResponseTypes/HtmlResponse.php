<?php

declare(strict_types= 1);

namespace SimpleSAML\Module\oidc\Server\ResponseTypes;

use Psr\Http\Message\ResponseInterface;
use League\OAuth2\Server\ResponseTypes\AbstractResponseType;

class HtmlResponse extends AbstractResponseType
{
    /**
     * @var string
     */
    private string $html;

    /**
     * @param string $html
     */
    public function setHtml($html): void
    {
        $this->html = $html;
    }

    /**
     * @param ResponseInterface $response
     *
     * @return ResponseInterface
     */
    public function generateHttpResponse(ResponseInterface $response)
    {
        $response->getBody()->write($this->html);

        return $response->withStatus(200)->withHeader('Content-Type', 'text/html');
    }
}
