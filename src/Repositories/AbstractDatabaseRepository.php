<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Repositories;

use SimpleSAML\Database;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;

abstract class AbstractDatabaseRepository
{
    /**
     * Bound variables a single statement may carry.
     *
     * SQLite refuses a statement binding more than 999 of them unless it was compiled with a higher
     * ceiling, which only became the default in 3.32. MySQL and PostgreSQL both allow 65535, so the
     * oldest SQLite a deployment might be running is what decides this for all three drivers: a
     * statement built to this ceiling runs everywhere, and one built to MySQL's does not.
     *
     * The ceiling is per statement rather than per row, so it is only ever reached by statements which
     * name their rows individually -- a multi row INSERT, or an UPDATE or DELETE listing keys. Those
     * split themselves against it via maxRowsPerStatement() instead of each choosing a batch size and
     * hoping it was chosen under the right limit.
     */
    protected const int MAX_BOUND_VARIABLES = 999;


    /**
     * ClientRepository constructor.
     * @throws \Exception
     */
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly Database $database,
        protected readonly ?ProtocolCache $protocolCache,
    ) {
    }


    public function getCacheKey(string $identifier): string
    {
        return is_string($tableName = $this->getTableName()) ?
        $tableName . '_' . $identifier :
        $identifier;
    }


    /**
     * How many rows a batched statement can name before it has to be split.
     *
     * Deriving this from MAX_BOUND_VARIABLES rather than writing a batch size by hand is what keeps the
     * two from drifting apart: a hand picked number is correct only for the statement it was picked for,
     * and stays behind when a column is added to it. Callers batch by the result rather than clamping
     * what they were asked for, so a bound handed in by a caller still means the number of rows worked,
     * however many statements that takes.
     *
     * @param positive-int $perRow Bound variables each named row contributes.
     * @param int $fixed Bound variables the statement carries however many rows it names.
     * @return positive-int
     */
    protected function maxRowsPerStatement(int $perRow, int $fixed = 0): int
    {
        return max(1, intdiv(self::MAX_BOUND_VARIABLES - $fixed, $perRow));
    }


    abstract public function getTableName(): ?string;
}
