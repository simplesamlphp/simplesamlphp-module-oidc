<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Codebooks;

enum RegistrationTypeEnum: string
{
    case Manual = 'manual';
    case FederatedAutomatic = 'federated_automatic';

    public function description(): string
    {
        return match ($this) {
            self::Manual => 'Manual',
            self::FederatedAutomatic => 'Federated Automatic',
        };
    }
}
