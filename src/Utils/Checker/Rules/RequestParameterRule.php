<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use Throwable;

class RequestParameterRule extends AbstractRule
{
    /**
     * @throws Throwable
     * @throws OidcServerException
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $queryParams = $request->getQueryParams();
        if (!array_key_exists('request', $queryParams)) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        /** @var ?string $stateValue */
        $stateValue = ($currentResultBag->get(StateRule::class))?->getValue();

        throw OidcServerException::requestNotSupported(
            'request object not supported',
            $redirectUri,
            null,
            $stateValue,
            $useFragmentInHttpErrorResponses
        );
    }
}
