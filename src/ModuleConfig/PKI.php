<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\ModuleConfig;

abstract class PKI
{
    final public const OPTION_PRIVATE_KEY_PASSPHRASE = 'pass_phrase';
    final public const OPTION_PRIVATE_KEY_FILENAME = 'privatekey';
    final public const DEFAULT_PRIVATE_KEY_FILENAME = 'oidc_module.key';
    final public const OPTION_CERTIFICATE_FILENAME = 'certificate';
    final public const DEFAULT_CERTIFICATE_FILENAME = 'oidc_module.crt';
}
