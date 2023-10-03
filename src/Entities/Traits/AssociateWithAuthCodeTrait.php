<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Traits;

trait AssociateWithAuthCodeTrait
{
    protected ?string $authCodeId = null;

    public function setAuthCodeId(?string $authCodeId): void
    {
        $this->authCodeId = $authCodeId;
    }

    public function getAuthCodeId(): ?string
    {
        return $this->authCodeId;
    }
}
