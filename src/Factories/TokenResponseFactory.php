<?php

declare(strict_types=1);

/*
 * This file is part of the simplesamlphp-module-oidc.
 *
 * Copyright (C) 2018 by the Spanish Research and Academic Network.
 *
 * This code was developed by Universidad de Córdoba (UCO https://www.uco.es)
 * for the RedIRIS SIR service (SIR: http://www.rediris.es/sir)
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace SimpleSAML\Module\oidc\Factories;

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;

class TokenResponseFactory
{
    public function __construct(
        private readonly ModuleConfig $moduleConfig,
        private readonly UserRepository $userRepository,
        private readonly IdTokenBuilder $idTokenBuilder,
        private readonly CryptKey $privateKey,
        private readonly LoggerService $loggerService,
    ) {
    }

    public function build(): TokenResponse
    {
        $tokenResponse = new TokenResponse(
            $this->userRepository,
            $this->idTokenBuilder,
            $this->privateKey,
            $this->loggerService,
        );
        $tokenResponse->setEncryptionKey($this->moduleConfig->getEncryptionKey());

        return $tokenResponse;
    }
}
