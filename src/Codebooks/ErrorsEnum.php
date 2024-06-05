<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ErrorsEnum: string
{
    case InvalidRequest = 'invalid_request';
    case InvalidClient = 'invalid_client';
    case InvalidIssuer = 'invalid_issuer';
    case NotFound = 'not_found';
    case ServerError = 'server_error';
    case TemporarilyUnavailable = 'temporarily_unavailable';
    case UnsupportedParameter = 'unsupported_parameter';
}
