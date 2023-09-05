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

namespace SimpleSAML\Module\oidc\Entity;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entity\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entity\Traits\OidcAuthCodeTrait;
use SimpleSAML\Module\oidc\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use SimpleSAML\Module\oidc\Entity\Interfaces\AuthCodeEntityInterface;

class AuthCodeEntity implements AuthCodeEntityInterface, MementoInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use OidcAuthCodeTrait;
    use RevokeTokenTrait;

    /**
     * @throws OidcServerException
     */
    public static function fromState(array $state): self
    {
        $authCode = new self();

        if (
            !is_string($state['scopes']) ||
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['client'], ClientEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state');
        }

        $stateScopes = json_decode($state['scopes'], true);

        if (!is_array($stateScopes)) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state: scopes');
        }

        $scopes = array_map(
            /**
             * @return \SimpleSAML\Module\oidc\Entity\ScopeEntity
             */
            function (string $scope) {
                return ScopeEntity::fromData($scope);
            },
            $stateScopes
        );

        $authCode->identifier = $state['id'];
        $authCode->scopes = $scopes;
        $authCode->expiryDateTime = \DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at'])
        );
        $authCode->userIdentifier = empty($state['user_id']) ? null : (string)$state['user_id'];
        $authCode->client = $state['client'];
        $authCode->isRevoked = (bool) $state['is_revoked'];
        $authCode->redirectUri = empty($state['redirect_uri']) ? null : (string)$state['redirect_uri'];
        $authCode->nonce = empty($state['nonce']) ? null : (string)$state['nonce'];

        return $authCode;
    }

    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->client->getIdentifier(),
            'is_revoked' => (int) $this->isRevoked(),
            'redirect_uri' => $this->getRedirectUri(),
            'nonce' => $this->getNonce(),
        ];
    }
}
