<?php


namespace SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Rules;


use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use OpenIDConnectServer\ClaimExtractor;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Server\Exceptions\OidcServerException;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Modules\OpenIDConnect\Utils\Checker\Result;

class RequestedClaimsRule extends AbstractRule
{
    private $clientRepository;

    private $claimExtractor;

    public function __construct(ClientRepositoryInterface $clientRepository, ClaimExtractor $claimExtractor)
    {
        $this->clientRepository = $clientRepository;
        $this->claimExtractor = $claimExtractor;
    }


    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        array $data
    ): ?ResultInterface {
        $claimsParam = $request->getQueryParams()['claims'] ?? null;
        $claims = json_decode($claimsParam, true);
        if (is_null($claims)) {
            return null;
        }
        $clientId = $request->getQueryParams()['client_id'] ?? $request->getServerParams()['PHP_AUTH_USER'] ?? null;

        if ($clientId === null) {
            throw OidcServerException::invalidRequest('client_id');
        }

        $client = $this->clientRepository->getClientEntity($clientId);
        if ($client instanceof ClientEntityInterface === false) {
            throw OidcServerException::invalidClient($request);
        }
        $authorizedClaims = [];
        foreach ($client->getScopes() as $scope) {
            $claimSet = $this->claimExtractor->getClaimSet($scope);
            if ($claimSet) {
                $authorizedClaims = array_merge($authorizedClaims, $claimSet->getClaims());
            }
        }
        // Remove requested claims that we aren't authorized for.
        $this->filterUnauthorizedClaims($claims['userinfo'], $authorizedClaims);
        $this->filterUnauthorizedClaims($claims['id_token'], $authorizedClaims);
        
        return new Result($this->getKey(), $claims);
    }

    private function filterUnauthorizedClaims(array &$requested, array $authorized) {
        $requested = array_filter(
            $requested,
            function ($key) use ($authorized) {
                return in_array($key, $authorized);
            },
            ARRAY_FILTER_USE_KEY
        );
    }
}