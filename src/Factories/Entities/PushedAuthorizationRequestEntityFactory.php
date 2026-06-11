<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2026 by the Spanish Research and Academic Network.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateTimeImmutable;
use SimpleSAML\Module\oidc\Entities\PushedAuthorizationRequestEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\OpenID\Exceptions\OpenIdException;

class PushedAuthorizationRequestEntityFactory
{
    final public const string REQUEST_URI_PREFIX = 'urn:ietf:params:oauth:request_uri:';

    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Helpers $helpers,
    ) {
    }

    /**
     * @param mixed[] $parameters
     * @throws \Exception
     */
    public function buildNew(
        string $clientId,
        array $parameters,
        ?DateTimeImmutable $expiresAt = null,
    ): PushedAuthorizationRequestEntity {
        $requestUri = self::REQUEST_URI_PREFIX . bin2hex(random_bytes(32));

        $expiresAt ??= $this->helpers->dateTime()->getUtc()
            ->add($this->moduleConfig->getParRequestUriTtl());

        return new PushedAuthorizationRequestEntity(
            $requestUri,
            $clientId,
            $parameters,
            $expiresAt,
        );
    }

    /**
     * @param mixed[] $state
     * @throws \SimpleSAML\OpenID\Exceptions\OpenIdException
     * @throws \JsonException
     * @throws \Exception
     */
    public function fromState(array $state): PushedAuthorizationRequestEntity
    {
        if (
            !is_string($requestUri = $state['request_uri']) ||
            !is_string($clientId = $state['client_id']) ||
            !is_string($parametersJson = $state['parameters']) ||
            !is_string($expiresAt = $state['expires_at'])
        ) {
            throw new OpenIdException('Invalid Pushed Authorization Request Entity state.');
        }

        /** @psalm-suppress MixedAssignment */
        $parameters = json_decode($parametersJson, true, 512, JSON_THROW_ON_ERROR);

        $isConsumed = (bool)($state['is_consumed'] ?? true);

        return new PushedAuthorizationRequestEntity(
            $requestUri,
            $clientId,
            is_array($parameters) ? $parameters : [],
            $this->helpers->dateTime()->getUtc($expiresAt),
            $isConsumed,
        );
    }
}
