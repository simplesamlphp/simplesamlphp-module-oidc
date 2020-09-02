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

namespace SimpleSAML\Modules\OpenIDConnect\Entity;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\OidcAuthCodeEntityInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Traits\OidcAuthCodeTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AuthCodeEntity implements OidcAuthCodeEntityInterface, MementoInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use OidcAuthCodeTrait;
    use RevokeTokenTrait;

    public static function fromState(array $state): self
    {
        $authCode = new self();

        $scopes = array_map(
            /**
             * @return \SimpleSAML\Modules\OpenIDConnect\Entity\ScopeEntity
             */
            function (string $scope) {
                return ScopeEntity::fromData($scope);
            },
            json_decode($state['scopes'], true)
        );

        $authCode->identifier = $state['id'];
        $authCode->scopes = $scopes;
        $authCode->expiryDateTime = \DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at'])
        );
        $authCode->userIdentifier = $state['user_id'];
        $authCode->client = $state['client'];
        $authCode->isRevoked = (bool) $state['is_revoked'];
        $authCode->redirectUri = $state['redirect_uri'];
        $authCode->nonce = $state['nonce'];

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
