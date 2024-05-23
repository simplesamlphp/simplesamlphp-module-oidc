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
use Exception;
use JsonException;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\MementoInterface;
use SimpleSAML\Module\oidc\Entities\Traits\OidcAuthCodeTrait;
use SimpleSAML\Module\oidc\Entities\Traits\RevokeTokenTrait;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Utils\TimestampGenerator;
use SimpleSAML\Module\oidc\Entities\Interfaces\AuthCodeEntityInterface;

class AuthCodeEntity implements AuthCodeEntityInterface, MementoInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use OidcAuthCodeTrait;
    use RevokeTokenTrait;

    /**
     * @throws OidcServerException|JsonException
     * @throws Exception
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

        $stateScopes = json_decode($state['scopes'], true, 512, JSON_THROW_ON_ERROR);

        if (!is_array($stateScopes)) {
            throw OidcServerException::serverError('Invalid Auth Code Entity state: scopes');
        }

        $scopes = array_map(
            /**
             * @return ScopeEntity
             */
            fn(string $scope) => ScopeEntity::fromData($scope),
            $stateScopes,
        );

        $authCode->identifier = $state['id'];
        $authCode->scopes = $scopes;
        $authCode->expiryDateTime = DateTimeImmutable::createFromMutable(
            TimestampGenerator::utc($state['expires_at']),
        );
        $authCode->userIdentifier = empty($state['user_id']) ? null : (string)$state['user_id'];
        $authCode->client = $state['client'];
        $authCode->isRevoked = (bool) $state['is_revoked'];
        $authCode->redirectUri = empty($state['redirect_uri']) ? null : (string)$state['redirect_uri'];
        $authCode->nonce = empty($state['nonce']) ? null : (string)$state['nonce'];

        return $authCode;
    }

    /**
     * @throws JsonException
     */
    public function getState(): array
    {
        return [
            'id' => $this->getIdentifier(),
            'scopes' => json_encode($this->scopes, JSON_THROW_ON_ERROR),
            'expires_at' => $this->getExpiryDateTime()->format('Y-m-d H:i:s'),
            'user_id' => $this->getUserIdentifier(),
            'client_id' => $this->client->getIdentifier(),
            'is_revoked' => (int) $this->isRevoked(),
            'redirect_uri' => $this->getRedirectUri(),
            'nonce' => $this->getNonce(),
        ];
    }
}
