<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;

class PromptRule implements RequestRule
{
    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;

    public function __construct(AuthSimpleFactory $authSimpleFactory)
    {
        $this->authSimpleFactory = $authSimpleFactory;
    }

    public function checkRule(ServerRequestInterface $request)
    {
        $authSimple = $this->authSimpleFactory->build($request);

        $queryParams = $request->getQueryParams();
        if (!array_key_exists('prompt', $queryParams)) {
            return;
        }

        $prompt = explode(" ", $queryParams['prompt']);
        if (count($prompt) > 1 && in_array('none', $prompt)) {
            throw OAuthServerException::invalidRequest('prompt', 'Invalid prompt parameter');
        }

        if (in_array('none', $prompt) && !$authSimple->isAuthenticated()) {
            throw OidcServerException::loginRequired(
                null,
                $request->getQueryParams()['redirect_uri'],
                null,
                $request->getQueryParams()['state']
            );
        }

        if (in_array('login', $prompt) && $authSimple->isAuthenticated()) {
            unset($queryParams['prompt']);
            $uri = $request->getUri()->withQuery(http_build_query($queryParams));
            $authSimple->logout(['ReturnTo' => (string) $uri]);
        }
    }
}
