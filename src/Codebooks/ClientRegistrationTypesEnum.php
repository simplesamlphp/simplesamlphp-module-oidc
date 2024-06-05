<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum ClientRegistrationTypesEnum: string
{
    case Automatic = 'automatic';
    case Explicit = 'explicit';
}
