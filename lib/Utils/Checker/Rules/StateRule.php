<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class StateRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        /** @var string|null $state */
        $state = $request->getQueryParams()['state'] ?? null;

        return new Result($this->getKey(), $state);
    }
}
