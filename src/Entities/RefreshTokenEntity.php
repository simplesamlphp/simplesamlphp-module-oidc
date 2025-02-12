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

namespace SimpleSAML\Module\oidc\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;
    use RevokeTokenTrait;
    use AssociateWithAuthCodeTrait;

    public function __construct(
        string $id,
        DateTimeImmutable $expiryDateTime,
        AccessTokenEntityInterface $accessTokenEntity,
        ?string $authCodeId = null,
        bool $isRevoked = false,
    ) {
        $this->setIdentifier($id);
        $this->setExpiryDateTime($expiryDateTime);
        $this->setAccessToken($accessTokenEntity);
        $this->setAuthCodeId($authCodeId);
        $this->isRevoked = $isRevoked;
    }

    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'access_token_id' => $this->getAccessToken()->getIdentifier(),
            'is_revoked' => $this->isRevoked(),
            'auth_code_id' => $this->getAuthCodeId(),
        ];
    }
}
