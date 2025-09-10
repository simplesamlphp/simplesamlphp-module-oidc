<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

class RequestedClaimsRule extends AbstractRule
{
    public function __construct(
        RequestParamsResolver $requestParamsResolver,
        Helpers $helpers,
        private readonly ClaimTranslatorExtractor $claimExtractor,
    ) {
        parent::__construct($requestParamsResolver, $helpers);
    }


    /**
     * @throws \Throwable
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?ResultInterface {
        /** @psalm-suppress MixedAssignment We'll check the type. */
        $claimsParam = $this->requestParamsResolver->getBasedOnAllowedMethods(
            ParamsEnum::Claims->value,
            $request,
            $allowedServerRequestMethods,
        );
        if ($claimsParam === null) {
            return null;
        }
        // In case the claims param is sent using request object, this will already be array type.
        /** @var ?array $claims */
        $claims = is_array($claimsParam) ?
        $claimsParam :
        json_decode((string)$claimsParam, true, 512, JSON_THROW_ON_ERROR);

        if (is_null($claims)) {
            return null;
        }
        /** @var \SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface $client */
        $client = $currentResultBag->getOrFail(ClientRule::class)->getValue();

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
            fn($key) => in_array($key, $authorized, true),
            ARRAY_FILTER_USE_KEY,
        );
    }
}
