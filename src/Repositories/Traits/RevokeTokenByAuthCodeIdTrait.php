<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Traits;

trait RevokeTokenByAuthCodeIdTrait
{
    public function revokeByAuthCodeId(string $authCodeId): void
    {
        $stmt = sprintf(
            "UPDATE %s SET is_revoked = 1 WHERE auth_code_id = :auth_code_id",
            $this->getTableName()
        );

        $this->database->write(
            $stmt,
            ['auth_code_id' => $authCodeId]
        );
    }
}
