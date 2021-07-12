<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Server\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use OpenIDConnectServer\Repositories\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Services\ConfigurationService;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;

/**
 * Class IdTokenResponse.
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 *
 * @see https://github.com/steverhoades/oauth2-openid-connect-server/blob/master/src/IdTokenResponse.php
 */
class IdTokenResponse extends BearerTokenResponse implements NonceResponseTypeInterface, AuthTimeResponseTypeInterface
{
    /**
     * @var IdentityProviderInterface
     */
    private $identityProvider;
    /**
     * @var ConfigurationService
     */
    private $configurationService;

    /**
     * @var IdTokenBuilder
     */
    protected $idTokenBuilder;

    /**
     * @var string|null
     */
    protected $nonce;

    /**
     * @var int|null
     */
    protected $authTime;

    public function __construct(
        IdentityProviderInterface $identityProvider,
        ConfigurationService $configurationService,
        IdTokenBuilder $idTokenBuilder
    ) {
        $this->identityProvider = $identityProvider;
        $this->idTokenBuilder = $idTokenBuilder;
        $this->configurationService = $configurationService;
    }

    /**
     * @return array
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        if (false === $this->isOpenIDRequest($accessToken->getScopes())) {
            return [];
        }

        // Per https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.5.4 certain claims
        // should only be added in certain scenarios. Allow deployer to control this.
        $addClaimsFromScopes = $this->configurationService
            ->getOpenIDConnectConfiguration()
            ->getBoolean('alwaysAddClaimsToIdToken', true);

        /** @var UserEntityInterface $userEntity */
        $userEntity = $this->identityProvider->getUserEntityByIdentifier($accessToken->getUserIdentifier());

        // TODO mivanci make released access token string immutable so we can generate at_hash properly
        $token = $this->idTokenBuilder->build(
            $userEntity,
            $this->accessToken,
            $addClaimsFromScopes,
            true,
            $this->getNonce(),
            $this->getAuthTime()
        );

        return [
            'id_token' => $token->toString(),
        ];
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     *
     * @return bool
     */
    private function isOpenIDRequest($scopes)
    {
        // Verify scope and make sure openid exists.
        foreach ($scopes as $scope) {
            if ('openid' === $scope->getIdentifier()) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $nonce
     */
    public function setNonce(string $nonce): void
    {
        $this->nonce = $nonce;
    }

    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @param int $authTime
     */
    public function setAuthTime(int $authTime): void
    {
        $this->authTime = $authTime;
    }

    /**
     * @return int|null
     */
    public function getAuthTime(): ?int
    {
        return $this->authTime;
    }
}
