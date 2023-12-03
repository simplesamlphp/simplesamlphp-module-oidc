<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use Throwable;

class RequestedClaimsRule extends AbstractRule
{
    public function __construct(private readonly ClaimTranslatorExtractor $claimExtractor)
    {
    }


    /**
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
        /** @var ?string $claimsParam */
        $claimsParam = $request->getQueryParams()['claims'] ?? null;
        if ($claimsParam === null) {
            return null;
        }
        /** @var ?array $claims */
        $claims = json_decode($claimsParam, true, 512, JSON_THROW_ON_ERROR);
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

    private function filterUnauthorizedClaims(array &$requestClaims, string $key, array $authorized): void
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
            fn($key) => in_array($key, $authorized),
            ARRAY_FILTER_USE_KEY
        );
    }
}
