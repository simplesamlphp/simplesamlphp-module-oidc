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
use SimpleSAML\Database;
use SimpleSAML\Module\oidc\Entities\Interfaces\AccessTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\RefreshTokenEntityInterface;
use SimpleSAML\Module\oidc\Entities\Traits\AssociateWithAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;

class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait;
    use EntityTrait;
    use RevokeTokenTrait;
    use AssociateWithAuthCodeTrait;

    /**
     * @throws \Exception
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public static function fromState(array $state): RefreshTokenEntityInterface
    {
        $refreshToken = new self();

        if (
            !is_string($state['id']) ||
            !is_string($state['expires_at']) ||
            !is_a($state['access_token'], AccessTokenEntityInterface::class)
        ) {
            throw OidcServerException::serverError('Invalid Refresh Token state');
        }

        $refreshToken->identifier = $state['id'];
        $refreshToken->expiryDateTime = DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at']),
        );
        $refreshToken->accessToken = $state['access_token'];
        $refreshToken->isRevoked = (bool) $state['is_revoked'];
        $refreshToken->authCodeId = empty($state['auth_code_id']) ? null : (string)$state['auth_code_id'];

        return $refreshToken;
    }

    public function getState(): array
    {
        $database = Database::getInstance();

        $revoked = $this->isRevoked() ? 'true' : 'false';
        if($database->getDriver() === 'mysql') {
            $revoked = (int) $this->isRevoked();
        }

        return [
            'id' => $this->getIdentifier(),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'access_token_id' => $this->getAccessToken()->getIdentifier(),
            'is_revoked' => $revoked,
            'auth_code_id' => $this->getAuthCodeId(),
        ];
    }
}
