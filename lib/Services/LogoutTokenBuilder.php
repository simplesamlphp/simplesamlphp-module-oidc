<?php

namespace SimpleSAML\Module\oidc\Services;

use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use stdClass;

class LogoutTokenBuilder
{
    protected JsonWebTokenBuilderService $jsonWebTokenBuilderService;

    public function __construct(
        ?JsonWebTokenBuilderService $jsonWebTokenBuilderService = null
    ) {
        $this->jsonWebTokenBuilderService = $jsonWebTokenBuilderService ?? new JsonWebTokenBuilderService();
    }

    /**
     * @throws OAuthServerException
     */
    public function forRelyingPartyAssociation(RelyingPartyAssociationInterface $relyingPartyAssociation): string
    {
        $logoutTokenBuilder = $this->jsonWebTokenBuilderService
            ->getDefaultJwtTokenBuilder()
            ->permittedFor($relyingPartyAssociation->getClientId())
            ->relatedTo($relyingPartyAssociation->getUserId())
            ->withClaim('events', ['http://schemas.openid.net/event/backchannel-logout' => new stdClass()])
        ;

        if ($relyingPartyAssociation->getSessionId() !== null) {
            $logoutTokenBuilder->withClaim('sid', $relyingPartyAssociation->getSessionId());
        }

        return $this->jsonWebTokenBuilderService->getSignedJwtTokenFromBuilder($logoutTokenBuilder)->toString();
    }
}
