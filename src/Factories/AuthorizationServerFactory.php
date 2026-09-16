<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

class AuthorizationServerFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AuthCodeGrant $authCodeGrant,
        private readonly ImplicitGrant $implicitGrant,
        private readonly RefreshTokenGrant $refreshTokenGrant,
        private readonly TokenResponse $tokenResponse,
        private readonly RequestRulesManager $requestRulesManager,
        private readonly CryptKey $privateKey,
        private readonly PreAuthCodeGrant $preAuthCodeGrant,
        private readonly LoggerService $loggerService,
    ) {
    }


    public function build(): AuthorizationServer
    {
        $authorizationServer = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->privateKey,
            $this->moduleConfig->getEncryptionKey(),
            $this->tokenResponse,
            $this->requestRulesManager,
            $this->loggerService,
        );

        $authorizationServer->enableGrantType(
            $this->authCodeGrant,
            $this->moduleConfig->getAccessTokenDuration(),
        );

        // A grant type left out of the enabled set is not on the server at all, so a request for it is
        // refused the way RFC 6749 has it (unsupported_response_type, unsupported_grant_type) even from a
        // client whose registration still names it. The authorization code grant can not be disabled.
        if ($this->moduleConfig->isGrantTypeEnabled(GrantTypesEnum::Implicit)) {
            $authorizationServer->enableGrantType(
                $this->implicitGrant,
                $this->moduleConfig->getAccessTokenDuration(),
            );
        }

        if ($this->moduleConfig->isGrantTypeEnabled(GrantTypesEnum::RefreshToken)) {
            $authorizationServer->enableGrantType(
                $this->refreshTokenGrant,
                $this->moduleConfig->getAccessTokenDuration(),
            );
        }

        if ($this->moduleConfig->getVciEnabled()) {
            $authorizationServer->enableGrantType(
                $this->preAuthCodeGrant,
                $this->moduleConfig->getAccessTokenDuration(),
            );
        }

        return $authorizationServer;
    }
}
