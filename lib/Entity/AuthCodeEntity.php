<?php

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * (c) Sergio Gómez <sergio@uco.es>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Modules\OpenIDConnect\Entity;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Modules\OpenIDConnect\Entity\Interfaces\MementoInterface;
use SimpleSAML\Modules\OpenIDConnect\Entity\Traits\RevokeTokenTrait;
use SimpleSAML\Modules\OpenIDConnect\Utils\TimestampGenerator;

class AuthCodeEntity implements AuthCodeEntityInterface, MementoInterface
{
    use EntityTrait, TokenEntityTrait, AuthCodeTrait, RevokeTokenTrait;
    

    public static function fromState(array $state)
    {
        $authCode = new self();

        $scopes = array_map(function ($scope) {
            return ScopeEntity::jsonUnserialize($scope);
        }, json_decode($state['scopes'], true));

        $authCode->identifier = $state['id'];
        $authCode->scopes = $scopes;
        $authCode->expiryDateTime = TimestampGenerator::utc($state['expires_at']);
        $authCode->userIdentifier = $state['user_id'];
        $authCode->client = $state['client'];
        $authCode->isRevoked = (bool) $state['is_revoked'];
        $authCode->redirectUri = $state['redirect_uri'];

        return $authCode;
    }

    public function getState(): array
    {
        return [
            'id' => $this->identifier,
            'scopes' => json_encode($this->scopes),
            'expires_at' => $this->expiryDateTime->format('Y-m-d H:i:s'),
            'user_id' => $this->userIdentifier,
            'client_id' => $this->client->getIdentifier(),
            'is_revoked' => $this->isRevoked,
            'redirect_uri' => $this->redirectUri,
        ];
    }
}
