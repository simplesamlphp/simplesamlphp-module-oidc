<?php

namespace SimpleSAML\Module\oidc\Utils\Checker\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;

class AcrValuesRule extends AbstractRule
{
    /**
     * @inheritDoc
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        bool $useFragmentInHttpErrorResponses = false,
        array $allowedServerRequestMethods = ['GET']
    ): ?ResultInterface {
        $acrValues = [
            'essential' => false,
            'values' => [],
        ];

        // Check if RequestedClaims rule contains acr
        /** @var Result $requestedClaimsResult  */
        if (($requestedClaimsResult = $currentResultBag->get(RequestedClaimsRule::class)) !== null) {
            // Format: https://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
            /**
             * "acr": {
             * "essential": true,
             * "value": "urn:mace:incommon:iap:silver",
             * or...
             * "values": [
             *      "urn:mace:incommon:iap:silver",
             *      "urn:mace:incommon:iap:bronze"
             * ]
             * }
             */
            $requestedAcrClaim = $requestedClaimsResult->getValue()['id_token']['acr'] ?? [];
            $acrValues['essential'] = $requestedAcrClaim['essential'] ?? false;
            $acrValues['values'] = array_merge(
                isset($requestedAcrClaim['value']) ? [$requestedAcrClaim['value']] : [],
                $requestedAcrClaim['values'] ?? []
            );
        }

        // Check for acr_values request parameter
        if (($acrValuesParam = $request->getQueryParams()['acr_values'] ?? null) !== null) {
            $acrValues['values'] = array_merge($acrValues['values'], explode(' ', $acrValuesParam));
        }

        return new Result($this->getKey(), empty($acrValues['values']) ? null : $acrValues);
    }
}
