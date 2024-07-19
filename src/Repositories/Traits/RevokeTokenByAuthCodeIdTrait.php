<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories\Traits;

use PDO;

trait RevokeTokenByAuthCodeIdTrait
{
    /**
     * @param   string  $authCodeId
     *
     * @return void
     */
    public function revokeByAuthCodeId(string $authCodeId): void
    {
        $revokedParam = [true, PDO::PARAM_BOOL];
        [$query, $bindParam] = $this->generateQuery($authCodeId, $revokedParam);
        $this->database->write((string)$query, (array)$bindParam);
    }

    /**
     * @param   string  $authCodeId
     * @param   array   $revokedParam
     *
     * @return array
     */
    protected function generateQuery(string $authCodeId, array $revokedParam): array
    {
        $query     = sprintf(
            'UPDATE %s SET is_revoked = 1 WHERE auth_code_id = :auth_code_id',
            $this->getTableName(),
        );
        $bindParam = ['auth_code_id' => $authCodeId, 'is_revoked' => $revokedParam];

        return [$query, $bindParam];
    }
}
