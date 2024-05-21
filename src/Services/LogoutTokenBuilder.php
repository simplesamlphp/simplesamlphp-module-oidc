<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use Exception;
use League\OAuth2\Server\Exception\OAuthServerException;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use stdClass;

class LogoutTokenBuilder
{
    public function __construct(
        protected JsonWebTokenBuilderService $jsonWebTokenBuilderService = new JsonWebTokenBuilderService()
    ) {
    }

    /**
     * @throws OAuthServerException|Exception
     * @psalm-suppress ArgumentTypeCoercion
     */
    public function forRelyingPartyAssociation(RelyingPartyAssociationInterface $relyingPartyAssociation): string
    {
        $logoutTokenBuilder = $this->jsonWebTokenBuilderService
            ->getProtocolJwtBuilder()
            ->withHeader('typ', 'logout+jwt')
            ->permittedFor($relyingPartyAssociation->getClientId())
            ->relatedTo($relyingPartyAssociation->getUserId())
            ->withClaim('events', ['http://schemas.openid.net/event/backchannel-logout' => new stdClass()])
        ;

        if ($relyingPartyAssociation->getSessionId() !== null) {
            $logoutTokenBuilder = $logoutTokenBuilder->withClaim('sid', $relyingPartyAssociation->getSessionId());
        }

        return $this->jsonWebTokenBuilderService->getSignedProtocolJwt($logoutTokenBuilder)->toString();
    }
}
