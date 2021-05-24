<?php


namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;


use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;

class RequestParameterRule extends AbstractRule
{
    public function checkRule(ServerRequestInterface $request, ResultBagInterface $currentResultBag, array $data): ?ResultInterface
    {
        $queryParams = $request->getQueryParams();
        if (!array_key_exists('request', $queryParams)) {
            return null;
        }

        /** @var string $redirectUri */
        $redirectUri = $currentResultBag->getOrFail(RedirectUriRule::class)->getValue();
        $state = $currentResultBag->get(StateRule::class);

        throw OidcServerException::requestNotSupported(
            'request object not supported',
            $redirectUri,
            null,
            $state ? $state->getValue() : null
        );
    }
}
