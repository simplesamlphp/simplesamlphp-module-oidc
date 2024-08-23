<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Server\RequestRules\Rules;

use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\ResultInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\Result;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\HttpMethodsEnum;

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
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET->value],
    ): ?ResultInterface {
        $acrValues = [
            'essential' => false,
            'values' => [],
        ];

        // Check if RequestedClaims rule contains acr
        /** @var \SimpleSAML\Module\oidc\Server\RequestRules\Result $requestedClaimsResult  */
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
            /** @var array $requestedAcrClaim */
            $requestedAcrClaim = $requestedClaimsResult->getValue()['id_token']['acr'] ?? [];
            $acrValues['essential'] = (bool)($requestedAcrClaim['essential'] ?? false);
            $acrValues['values'] = array_merge(
                isset($requestedAcrClaim['value']) ? [$requestedAcrClaim['value']] : [],
                isset($requestedAcrClaim['values']) && is_array($requestedAcrClaim['values']) ?
                    $requestedAcrClaim['values'] : [],
            );
        }

        // Check for acr_values request parameter
        $acrValuesParam = $this->getRequestParamBasedOnAllowedMethods(
            'acr_values',
            $request,
            $loggerService,
            $allowedServerRequestMethods,
        );
        if ($acrValuesParam !== null) {
            $acrValues['values'] = array_merge($acrValues['values'], explode(' ', $acrValuesParam));
        }

        return new Result($this->getKey(), empty($acrValues['values']) ? null : $acrValues);
    }
}
