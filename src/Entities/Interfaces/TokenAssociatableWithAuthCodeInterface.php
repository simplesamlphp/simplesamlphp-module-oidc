<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Entities\Interfaces;

interface TokenAssociatableWithAuthCodeInterface
{
    /**
     * @param string|null $authCodeId Set to auth_code_id or null to unset it.
     */
    public function setAuthCodeId(?string $authCodeId): void;

    /**
     * @return string|null
     */
    public function getAuthCodeId(): ?string;
}
