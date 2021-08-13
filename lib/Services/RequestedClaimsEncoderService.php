<?php


namespace SimpleSAML\Modules\OpenIDConnect\Services;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity;

/**
 * OIDC allows clients to request specific claims, and not just scopes. The oauth2 server library
 * does not seem to have an easy way to tie into authz and refresh token generation, making it difficult to
 * associated these claims with tokens. A short term workaround is to encode them as scope
 * Class RequestedClaimsEncoderService
 * @package SimpleSAML\Modules\OpenIDConnect\Services
 */
class RequestedClaimsEncoderService
{
    private $claimPrefix = '_claims_requested_';

    public function encodeRequestedClaimsAsScope($requestedClaims): ?ScopeEntityInterface
    {
        if (empty($requestedClaims)) {
            return null;
        }
        return ScopeEntity::fromData(
            $this->claimPrefix . base64_encode(json_encode($requestedClaims)),
            'workaround for storing request claims'
        );
    }

    public function decodeScopesToRequestedClaims(array $scopes): ?array
    {
        foreach ($scopes as $scope) {
            $scopeName = ($scope instanceof ScopeEntityInterface) ? $scope->getIdentifier() : $scope;
            $matches = [];
            if (preg_match('/^' . preg_quote($this->claimPrefix) . '(.*)$/', $scopeName, $matches) === 1) {
                return json_decode(base64_decode($matches[1]), true);
            }
        }
        return null;
    }

}