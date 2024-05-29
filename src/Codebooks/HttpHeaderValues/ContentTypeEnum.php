<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks\HttpHeaderValues;

enum ContentTypeEnum: string
{
    case ApplicationEntityStatementJwt = 'application/entity-statement+jwt';
}
