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
use SimpleSAML\OpenID\Codebooks\ParamsEnum;

/**
 * @extends AbstractRule<array|null>
 */
class AcrValuesRule extends AbstractRule
{
    /**
     * @inheritDoc
     *
     * @param ResponseModeInterface $responseMode
     * @param HttpMethodsEnum[] $allowedServerRequestMethods
     */
    public function checkRule(
        ServerRequestInterface $request,
        ResultBagInterface $currentResultBag,
        LoggerService $loggerService,
        array $data = [],
        ResponseModeInterface $responseMode = new QueryResponseMode(),
        array $allowedServerRequestMethods = [HttpMethodsEnum::GET],
    ): ?Result {
        $loggerService->debug('AcrValuesRule::checkRule');

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
        $acrValuesParam = $this->requestParamsResolver->getAsStringBasedOnAllowedMethods(
            ParamsEnum::AcrValues->value,
            $request,
            $allowedServerRequestMethods,
        );
        if ($acrValuesParam !== null) {
            $acrValues['values'] = array_merge($acrValues['values'], explode(' ', $acrValuesParam));
        }

        // Fall back to the client's registered default_acr_values when the request specified no acr (via the
        // claims parameter or acr_values). OIDC DCR 1.0: default_acr_values are the Default requested ACRs.
        if ($acrValues['values'] === []) {
            $client = $currentResultBag->get(ClientRule::class)?->getValue();
            if ($client instanceof ClientEntityInterface) {
                $acrValues['values'] = $client->getDefaultAcrValues();
            }
        }

        return new Result($this->getKey(), empty($acrValues['values']) ? null : $acrValues);
    }
}
