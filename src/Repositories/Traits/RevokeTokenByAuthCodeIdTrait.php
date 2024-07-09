<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Traits;

use PDO;

trait RevokeTokenByAuthCodeIdTrait
{
    public function revokeByAuthCodeId(string $authCodeId): void
    {
        $stmt = sprintf(
            "UPDATE %s SET is_revoked = :is_revoked WHERE auth_code_id = :auth_code_id",
            $this->getTableName(),
        );

        $this->database->write(
            $stmt,
            [
                'auth_code_id' => $authCodeId,
                'is_revoked' => [true, PDO::PARAM_BOOL],
            ],
        );
    }
}
