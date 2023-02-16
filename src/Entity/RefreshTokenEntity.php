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
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use SimpleSAML\Module\oidc\Entity\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entity\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;
    use RevokeTokenTrait;
    use AssociateWithAuthCodeTrait;

    public static function fromState(array $state): RefreshTokenEntityInterface
    {
        $refreshToken = new self();

        $refreshToken->identifier = $state['id'];
        $refreshToken->expiryDateTime = \DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at'])
        );
        $refreshToken->accessToken = $state['access_token'];
        $refreshToken->isRevoked = (bool) $state['is_revoked'];
        $refreshToken->authCodeId = $state['auth_code_id'];

        return $refreshToken;
    }

    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'access_token_id' => $this->getAccessToken()->getIdentifier(),
            'is_revoked' => (int) $this->isRevoked(),
            'auth_code_id' => $this->getAuthCodeId(),
        ];
    }
}
