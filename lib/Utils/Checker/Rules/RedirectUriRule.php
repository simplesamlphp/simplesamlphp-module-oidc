<?php

namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;

class RedirectUriRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();
        if (! $client instanceof ClientEntityInterface) {
            throw new \LogicException('Can not check redirect_uri, client is not ClientEntityInterface.');
        }

        /** @var string|null $redirectUri */
        $redirectUri = $request->getQueryParams()['redirect_uri'] ?? null;

        // On OAuth2 redirect_uri is optional if there is only one registered, however we will always require it
        // since this is OIDC oriented package and in OIDC this parameter is required.
        if ($redirectUri === null) {
            throw OidcServerException::invalidRequest('redirect_uri');
        }

        /** @psalm-suppress PossiblyInvalidArgument */
        if (
            \is_string($client->getRedirectUri()) &&
            (\strcmp($client->getRedirectUri(), $redirectUri) !== 0)
        ) {
            throw OidcServerException::invalidClient($request);
        } elseif (
            \is_array($client->getRedirectUri()) &&
            \in_array($redirectUri, $client->getRedirectUri(), true) === false
        ) {
            throw OidcServerException::invalidClient($request);
        }

        return new Result($this->getKey(), $redirectUri);
    }
}
