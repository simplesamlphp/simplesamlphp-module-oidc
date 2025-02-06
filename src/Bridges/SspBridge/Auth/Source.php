<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Bridges\SspBridge\Auth;

class Source
{
    public function getSources(): array
    {
        return \SimpleSAML\Auth\Source::getSources();
    }
}
