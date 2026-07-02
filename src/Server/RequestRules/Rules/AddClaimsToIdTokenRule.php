<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\ResponseModeInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

/**
 * Decides whether the user's (scope-derived) claims should be released in the ID Token.
 *
 * This is true when either:
 *  - the response type is exactly `id_token` (there is no access token, so the client cannot obtain the claims
 *    from the UserInfo endpoint and they must go in the ID Token); or
 *  - the client is configured with the administrator-only `add_claims_to_id_token` option (the client wants its
 *    claims in the ID Token regardless, e.g. because it never calls the UserInfo endpoint).
 *
 * @extends AbstractRule<bool>
 */
class AddClaimsToIdTokenRule extends AbstractRule
{
    /**
     * @inheritDoc
     *
     * @throws \Throwable
     *
     * @param ResponseModeInterface $responseMode
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $responseType = $currentResultBag->getOrFail(ResponseTypeRule::class)->getValue();

        $addClaimsToIdToken = $responseType === "id_token";

        // Honor the per-client option. The client is resolved by ClientRule, which is predefined in the result bag
        // before this rule runs; if it is not available for some reason, fall back to the response-type decision.
        $client = $currentResultBag->get(ClientRule::class)?->getValue();
        if ($client instanceof ClientEntityInterface && $client->getAddClaimsToIdToken()) {
            $addClaimsToIdToken = true;
        }

        return new Result($this->getKey(), $addClaimsToIdToken);
    }
}
