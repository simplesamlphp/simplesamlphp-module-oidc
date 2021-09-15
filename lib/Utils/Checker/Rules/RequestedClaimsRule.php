<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OpenIDConnectServer\ClaimExtractor;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class RequestedClaimsRule extends AbstractRule
{
    private $claimExtractor;

    public function __construct(ClaimExtractor $claimExtractor)
    {
        $this->claimExtractor = $claimExtractor;
    }


    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $claimsParam = $request->getQueryParams()['claims'] ?? null;
        if ($claimsParam === null) {
            return null;
        }
        $claims = json_decode($claimsParam, true);
        if (is_null($claims)) {
            return null;
        }
        /** @var ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientIdRule::class)->getValue();

        $authorizedClaims = [];
        foreach ($client->getScopes() as $scope) {
            $claimSet = $this->claimExtractor->getClaimSet($scope);
            if ($claimSet) {
                $authorizedClaims = array_merge($authorizedClaims, $claimSet->getClaims());
            }
        }
        $authorizedClaims = array_merge($authorizedClaims, ClaimTranslatorExtractor::REGISTERED_CLAIMS);

        // Remove requested claims that we aren't authorized for.
        $this->filterUnauthorizedClaims($claims, 'userinfo', $authorizedClaims);
        $this->filterUnauthorizedClaims($claims, 'id_token', $authorizedClaims);

        return new Result($this->getKey(), $claims);
    }

    private function filterUnauthorizedClaims(array &$requestClaims, string $key, array $authorized)
    {
        if (!array_key_exists($key, $requestClaims)) {
            return;
        }
        $requested = $requestClaims[$key];
        if (!is_array($requested)) {
            unset($requestClaims[$key]);
            return;
        }
        $requestClaims[$key] = array_filter(
            $requested,
            function ($key) use ($authorized) {
                return in_array($key, $authorized);
            },
            ARRAY_FILTER_USE_KEY
        );
    }
}
