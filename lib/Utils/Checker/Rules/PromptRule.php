<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Factories\AuthSimpleFactory;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\RequestRuleInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

class PromptRule implements RequestRuleInterface
{
    /**
     * @var AuthSimpleFactory
     */
    private $authSimpleFactory;

    public function __construct(AuthSimpleFactory $authSimpleFactory)
    {
        $this->authSimpleFactory = $authSimpleFactory;
    }

    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        $authSimple = $this->authSimpleFactory->build($request);

        $queryParams = $request->getQueryParams();
        if (!array_key_exists('prompt', $queryParams)) {
            return null;
        }

        $prompt = explode(" ", $queryParams['prompt']);
        if (count($prompt) > 1 && in_array('none', $prompt, true)) {
            throw OAuthServerException::invalidRequest('prompt', 'Invalid prompt parameter');
        }

        if (in_array('none', $prompt, true) && !$authSimple->isAuthenticated()) {
            throw OidcServerException::loginRequired(
                null,
                $queryParams['redirect_uri'],
                null,
                $queryParams['state'] ?? null
            );
        }

        if (in_array('login', $prompt, true) && $authSimple->isAuthenticated()) {
            unset($queryParams['prompt']);
            $uri = $request->getUri()->withQuery(http_build_query($queryParams));
            $authSimple->logout(['ReturnTo' => (string) $uri]);
        }

        return null;
    }
}
