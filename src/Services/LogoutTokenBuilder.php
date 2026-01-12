<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Services;

use SimpleSAML\Module\oidc\Factories\CoreFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Server\Associations\Interfaces\RelyingPartyAssociationInterface;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Core;
use stdClass;

class LogoutTokenBuilder
{
    protected Core $core;

    public function __construct(
        protected ModuleConfig $moduleConfig = new ModuleConfig(),
        protected LoggerService $loggerService = new LoggerService(),
        ?CoreFactory $coreFactory = null,
    ) {
        $this->core = ($coreFactory ?? new CoreFactory(
            $this->moduleConfig,
            $this->loggerService,
        ))->build();
    }

    /**
     * @throws \Exception
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     * @psalm-suppress ArgumentTypeCoercion
     */
    public function forRelyingPartyAssociation(RelyingPartyAssociationInterface $relyingPartyAssociation): string
    {
        $protocolSignatureKeyPairBag = $this->moduleConfig->getProtocolSignatureKeyPairBag();
        $protocolSignatureKeyPair = $protocolSignatureKeyPairBag->getFirstOrFail();

        // ID Token signing algorithm that the client wants. As per spec, the
        // same algorithm should be used for Logout Token.
        if (is_string($idTokenSignedResponseAlg = $relyingPartyAssociation->getClientIdTokenSignedResponseAlg())) {
            $protocolSignatureKeyPair = $protocolSignatureKeyPairBag->getFirstByAlgorithmOrFail(
                SignatureAlgorithmEnum::from($idTokenSignedResponseAlg),
            );
        }

        $currentTimestamp = $this->core->helpers()->dateTime()->getUtc()->getTimestamp();

        $payload = array_filter([
            ClaimsEnum::Iss->value => $this->moduleConfig->getIssuer(),
            ClaimsEnum::Iat->value => $currentTimestamp,
            ClaimsEnum::Exp->value => $this->core->helpers()->dateTime()->getUtc()->add(
                $this->moduleConfig->getAccessTokenDuration(),
            )->getTimestamp(),
            ClaimsEnum::Jti->value => $this->core->helpers()->random()->string(),
            ClaimsEnum::Aud->value => $relyingPartyAssociation->getClientId(),
            ClaimsEnum::Sub->value => $relyingPartyAssociation->getUserId(),
            ClaimsEnum::Events->value => ['http://schemas.openid.net/event/backchannel-logout' => new stdClass()],
            ClaimsEnum::Sid->value => $relyingPartyAssociation->getSessionId(),
        ]);

        $header = [
            ClaimsEnum::Kid->value => $protocolSignatureKeyPair->getKeyPair()->getKeyId(),
            ClaimsEnum::Typ->value => JwtTypesEnum::LogoutJwt->value,
        ];

        return $this->core->logoutTokenFactory()->fromData(
            $protocolSignatureKeyPair->getKeyPair()->getPrivateKey(),
            $protocolSignatureKeyPair->getSignatureAlgorithm(),
            $payload,
            $header,
        )->getToken();
    }
}
