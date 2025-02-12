<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

use SimpleSAML\Locale\Translate;

enum RegistrationTypeEnum: string
{
    case Manual = 'manual';
    case FederatedAutomatic = 'federated_automatic';

    public function description(): string
    {
        return match ($this) {
            self::Manual => Translate::noop('Manual'),
            self::FederatedAutomatic => Translate::noop('Federated Automatic'),
        };
    }
}
