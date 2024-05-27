<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

use SimpleSAML\Module as SspModule;

class Module
{
    public function getModuleUrl(string $resource, array $parameters = []): string
    {
        return SspModule::getModuleURL($resource, $parameters);
    }
}
