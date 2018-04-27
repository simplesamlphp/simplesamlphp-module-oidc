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

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class RefreshTokenEntity implements RefreshTokenEntityInterface, MementoInterface
{
    use RefreshTokenTrait, EntityTrait, RevokeTokenTrait;

    public static function fromState(array $state)
    {
        $refreshToken = new self();

        $refreshToken->identifier = $state['id'];
        $refreshToken->expiryDateTime = TimestampGenerator::utc($state['expires_at']);
        $refreshToken->accessToken = $state['access_token'];
        $refreshToken->isRevoked = $state['is_revoked'];

        return $refreshToken;
    }

    public function getState(): array
    {
        return [
            'id' => $this->identifier,
            'expires_at' => $this->expiryDateTime->format('Y-m-d H:i:s'),
            'access_token_id' => $this->accessToken->getIdentifier(),
            'is_revoked' => $this->isRevoked,
        ];
    }
}
