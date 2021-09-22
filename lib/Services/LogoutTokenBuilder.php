<?php

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;

class LogoutTokenBuilder
{
    protected JsonWebTokenBuilderService $jwtTokenBuilderService;

    public function __construct(
        ?JsonWebTokenBuilderService $jwtTokenBuilderService = null
    ) {
        $this->jwtTokenBuilderService = $jwtTokenBuilderService ?? new JsonWebTokenBuilderService();
    }

    public function forRelyingPartyAssociation(RelyingPartyAssociationInterface $relyingPartyAssociation): string
    {
        $logoutTokenBuilder = $this->jwtTokenBuilderService
            ->getDefaultJwtTokenBuilder()
            ->permittedFor($relyingPartyAssociation->getClientId())
            ->relatedTo($relyingPartyAssociation->getUserId())
            ->withClaim(
                'events',
                json_encode(
                    ['http://schemas.openid.net/event/backchannel-logout' => []],
                    JSON_FORCE_OBJECT | JSON_UNESCAPED_SLASHES
                )
            )
        ;

        if ($relyingPartyAssociation->getSessionId() !== null) {
            $logoutTokenBuilder->withClaim('sid', $relyingPartyAssociation->getSessionId());
        }

        return $this->jwtTokenBuilderService->getSignedJwtTokenFromBuilder($logoutTokenBuilder)->toString();
    }
}
