<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entity\Traits;

trait AssociateWithAuthCodeTrait
{
    /**
     * @var string|null $authCodeId
     */
    protected $authCodeId;

    public function setAuthCodeId(?string $authCodeId): void
    {
        $this->authCodeId = $authCodeId;
    }

    public function getAuthCodeId(): ?string
    {
        return $this->authCodeId;
    }
}
