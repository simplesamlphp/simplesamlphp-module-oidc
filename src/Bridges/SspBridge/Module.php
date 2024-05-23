<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge;

class Module
{
    public function getModuleUrl(string $resource, array $parameters = []): string
    {
        return \SimpleSAML\Module::getModuleURL($resource, $parameters);
    }
}
