<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

/**
 * Which surface a Status List status change came through, as recorded in the audit trail.
 */
enum StatusChangeSourceEnum: string
{
    /** The authenticated status API endpoint, acting for a named API token principal. */
    case Api = 'api';

    /** The administration UI, acting for a signed in administrator. */
    case Admin = 'admin';

    /** A scheduled task, with no human or API principal behind it. */
    case Cron = 'cron';
}
