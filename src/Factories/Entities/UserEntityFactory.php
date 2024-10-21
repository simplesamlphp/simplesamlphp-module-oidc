<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories\Entities;

use SimpleSAML\Module\oidc\Entities\UserEntity;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;

class UserEntityFactory
{
    public function __construct(
        protected readonly Helpers $helpers,
    ) {
    }

    public function fromData(string $identifier, array $claims = []): UserEntity
    {
        $createdAt = $updatedAt = $this->helpers->dateTime()->getUtc();

        return new UserEntity(
            $identifier,
            $createdAt,
            $updatedAt,
            $claims,
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function fromState(array $state): UserEntity
    {
        if (
            !is_string($state['id']) ||
            !is_string($state['claims']) ||
            !is_string($state['updated_at']) ||
            !is_string($state['created_at'])
        ) {
            throw OidcServerException::serverError('Invalid user entity data');
        }

        $identifier = $state['id'];
        $claims = json_decode($state['claims'], true, 512, JSON_INVALID_UTF8_SUBSTITUTE);

        if (!is_array($claims)) {
            throw OidcServerException::serverError('Invalid user entity data');
        }
        $updatedAt = $this->helpers->dateTime()->getUtc($state['updated_at']);
        $createdAt = $this->helpers->dateTime()->getUtc($state['created_at']);

        return new UserEntity(
            $identifier,
            $createdAt,
            $updatedAt,
            $claims,
        );
    }
}
