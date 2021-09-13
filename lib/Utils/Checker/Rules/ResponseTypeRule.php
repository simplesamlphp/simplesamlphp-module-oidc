<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class ResponseTypeRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false
    ): ?ResultInterface {
        $queryParams = $request->getQueryParams();

        if (!isset($queryParams['response_type']) || !isset($queryParams['client_id'])) {
            throw  OidcServerException::invalidRequest('Missing response_type');
        }

        // TODO consider checking for supported response types, for example, from configuration...

        return new Result($this->getKey(), $queryParams['response_type']);
    }
}
