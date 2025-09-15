<?php

declare(strict_types=1);

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

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use RuntimeException;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Repositories\Interfaces\IdentityProviderInterface;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AcrResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\AuthTimeResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\NonceResponseTypeInterface;
use SimpleSAML\Module\oidc\Server\ResponseTypes\Interfaces\SessionIdResponseTypeInterface;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;

/**
 * Class IdTokenResponse.
 *
 * @author Steve Rhoades <sedonami@gmail.com>
 * @license http://opensource.org/licenses/MIT MIT
 *
 * @see https://github.com/steverhoades/oauth2-openid-connect-server/blob/master/src/IdTokenResponse.php
 */
class TokenResponse extends BearerTokenResponse implements
    // phpcs:ignore
    NonceResponseTypeInterface,
    // phpcs:ignore
    AuthTimeResponseTypeInterface,
    // phpcs:ignore
    AcrResponseTypeInterface,
    // phpcs:ignore
    SessionIdResponseTypeInterface
{
    protected ?string $nonce = null;

    protected ?int $authTime = null;

    protected ?string $acr = null;

    protected ?string $sessionId = null;

    /**
     * @var \League\OAuth2\Server\Entities\AccessTokenEntityInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $accessToken;

    /**
     * @var \League\OAuth2\Server\Entities\RefreshTokenEntityInterface
     * @psalm-suppress PropertyNotSetInConstructor
     */
    protected $refreshToken;

    public function __construct(
        private readonly IdentityProviderInterface $identityProvider,
        protected IdTokenBuilder $idTokenBuilder,
        CryptKey $privateKey,
        protected LoggerService $loggerService,
    ) {
        $this->privateKey = $privateKey;
    }

    /**
     * @param \League\OAuth2\Server\Entities\AccessTokenEntityInterface $accessToken
     * @return array
     * @throws \Exception
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        if ($accessToken instanceof AccessTokenEntity === false) {
            throw new RuntimeException('AccessToken must be ' . AccessTokenEntity::class);
        }

        $extraParams = [];

        if ($this->isOpenIDRequest($accessToken->getScopes())) {
            $extraParams = [
                ...$extraParams,
                ...$this->prepareIdTokenExtraParam($accessToken),
            ];
        }

        // For VCI, in token response for authorization code flow we need to return authorization details.
        if (
            ($flowType = $accessToken->getFlowTypeEnum()) !== null &&
            $flowType->isVciFlow() &&
            $accessToken->getAuthorizationDetails() !== null
        ) {
            $extraParams = [
                ...$extraParams,
//                ...$this->prepareVciAuthorizationDetailsExtraParam($accessToken),
            ];
        }

        return array_filter($extraParams);
    }

    protected function prepareIdTokenExtraParam(AccessTokenEntity $accessToken): array
    {
        $userIdentifier = $accessToken->getUserIdentifier();

        if (empty($userIdentifier)) {
            throw OidcServerException::accessDenied('No user identifier present in AccessToken.');
        }

        $userEntity = $this->identityProvider->getUserEntityByIdentifier((string)$userIdentifier);

        if (empty($userEntity)) {
            throw OidcServerException::accessDenied('No user available for provided user identifier.');
        }

        $token = $this->idTokenBuilder->build(
            $userEntity,
            $accessToken,
            false,
            true,
            $this->getNonce(),
            $this->getAuthTime(),
            $this->getAcr(),
            $this->getSessionId(),
        );

        return [
            'id_token' => $token->toString(),
        ];
    }

    protected function prepareVciAuthorizationDetailsExtraParam(AccessTokenEntity $accessToken): array
    {
        $normalizedAuthorizationDetails = [];

        $this->loggerService->debug(
            'TokenResponse::prepareAuthorizationDetailsExtraParam',
            ['accessTokenAuthorizationDetails' => $accessToken->getAuthorizationDetails()],
        );

        if (($accessTokenAuthorizationDetails = $accessToken->getAuthorizationDetails()) === null) {
            return $normalizedAuthorizationDetails;
        }

        /** @psalm-suppress MixedAssignment */
        foreach ($accessTokenAuthorizationDetails as $authorizationDetail) {
            if (
                (isset($authorizationDetail['type'])) &&
                ($authorizationDetail['type']) === 'openid_credential'
            ) {
                /** @psalm-suppress MixedAssignment */
                $credentialConfigurationId = $authorizationDetail['credential_configuration_id'] ?? null;
                if ($credentialConfigurationId !== null) {
                    $authorizationDetail['credential_identifiers'] = [$credentialConfigurationId];
                }
                $normalizedAuthorizationDetails[] = $authorizationDetail;
            }
        }

        $this->loggerService->debug(
            'TokenResponse::prepareAuthorizationDetailsExtraParam. Summarized authorization details: ',
            ['authorizationDetails' => $normalizedAuthorizationDetails],
        );

        return ['authorization_details' => $normalizedAuthorizationDetails];
    }

    /**
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     *
     * @return bool
     */
    private function isOpenIDRequest(array $scopes): bool
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
     * @param string|null $nonce
     */
    public function setNonce(?string $nonce): void
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
     * @param int|null $authTime
     */
    public function setAuthTime(?int $authTime): void
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

    public function setAcr(?string $acr): void
    {
        $this->acr = $acr;
    }

    public function getAcr(): ?string
    {
        return $this->acr;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function setSessionId(?string $sessionId): void
    {
        $this->sessionId = $sessionId;
    }
}
