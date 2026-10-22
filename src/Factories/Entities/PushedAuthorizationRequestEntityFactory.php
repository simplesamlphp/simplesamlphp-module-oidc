<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use DateInterval;
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
     * A request given no expiry expires after the configured lifetime, or after $maxTtl when that ends sooner.
     *
     * @param mixed[] $parameters
     * @throws \Exception
     */
    public function fromData(
        string $clientId,
        array $parameters,
        ?DateTimeImmutable $expiresAt = null,
        ?DateInterval $maxTtl = null,
    ): PushedAuthorizationRequestEntity {

        $requestUri = self::REQUEST_URI_PREFIX . $this->helpers->random()->getIdentifier(32);

        if ($expiresAt === null) {
            $now = $this->helpers->dateTime()->getUtc();
            $expiresAt = $now->add($this->moduleConfig->getParRequestUriTtl());

            if ($maxTtl !== null && $now->add($maxTtl) < $expiresAt) {
                $expiresAt = $now->add($maxTtl);
            }
        }

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
