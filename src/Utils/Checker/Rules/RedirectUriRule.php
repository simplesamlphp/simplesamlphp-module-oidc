<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use Throwable;

class RedirectUriRule extends AbstractRule
{
    /**
     * @inheritDoc
     * @throws Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();
        if (! $client instanceof ClientEntityInterface) {
            throw new LogicException('Can not check redirect_uri, client is not ClientEntityInterface.');
        }

        /** @var string|null $redirectUri */
        $redirectUri = $request->getQueryParams()['redirect_uri'] ?? null;

        // On OAuth2 redirect_uri is optional if there is only one registered, however we will always require it
        // since this is OIDC oriented package and in OIDC this parameter is required.
        if ($redirectUri === null) {
            throw OidcServerException::invalidRequest('redirect_uri');
        }

        $clientRedirectUri = $client->getRedirectUri();
        if (is_string($clientRedirectUri) && (strcmp($clientRedirectUri, $redirectUri) !== 0)) {
            throw OidcServerException::invalidClient($request);
        } elseif (
            is_array($clientRedirectUri) &&
            in_array($redirectUri, $clientRedirectUri, true) === false
        ) {
            throw OidcServerException::invalidRequest('redirect_uri');
        }

        return new Result($this->getKey(), $redirectUri);
    }
}
