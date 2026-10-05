<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

use function is_string;
use function preg_match;

/**
 * The `dpop_jkt` authorization request parameter (RFC 9449 section 10): the JWK SHA-256 thumbprint (RFC 7638) of the
 * key the client is to make its DPoP proof with when it redeems the authorization code, which the code is bound to.
 * It comes as a request parameter, or as a claim of the Request Object, and is checked at the authorization
 * endpoint and the pushed authorization request endpoint alike.
 *
 * A SHA-256 hash in base64url without padding is 43 characters of that alphabet; any other value is refused as
 * `invalid_request`. One sent without a value is treated as omitted (RFC 6749 section 3.1).
 *
 * @extends \SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule<string|null>
 */
class DpopJktRule extends AbstractRule
{
    protected const string THUMBPRINT_PATTERN = '/^[A-Za-z0-9_-]{43}\z/';


    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param \SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface $responseMode
     * @param \SimpleSAML\OpenID\Codebooks\HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('DpopJktRule::checkRule');

        /** @var mixed $dpopJkt */
        $dpopJkt = $this->requestParamsResolver->getBasedOnAllowedMethods(
            ClaimsEnum::DpopJkt->value,
            $request,
            $allowedServerRequestMethods,
        );

        if ($dpopJkt === null || $dpopJkt === '') {
            return new Result($this->getKey(), null);
        }

        if (is_string($dpopJkt) && preg_match(self::THUMBPRINT_PATTERN, $dpopJkt) === 1) {
            return new Result($this->getKey(), $dpopJkt);
        }

        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

        $loggerService->notice(
            'Authorization request rejected: `dpop_jkt` is not a JWK SHA-256 thumbprint.',
            ['client_id' => $client->getIdentifier()],
        );

        throw OidcServerException::invalidRequest(
            ClaimsEnum::DpopJkt->value,
            'The dpop_jkt parameter must be the base64url-encoded JWK SHA-256 Thumbprint of a key.',
            null,
            $currentResultBag->getOrFail(ClientRedirectUriRule::class)->getValue(),
            $currentResultBag->getOrFail(StateRule::class)->getValue(),
            $responseMode,
        );
    }
}
