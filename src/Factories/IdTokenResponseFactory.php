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
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;

class IdTokenResponseFactory
{
    /**
     * @var UserRepository
     */
    private UserRepository $userRepository;
    /**
     * @var IdTokenBuilder
     */
    private IdTokenBuilder $idTokenBuilder;
    /**
     * @var CryptKey
     */
    private CryptKey $privateKey;
    /**
     * @var string
     */
    private string $encryptionKey;

    public function __construct(
        UserRepository $userRepository,
        IdTokenBuilder $idTokenBuilder,
        CryptKey $privateKey,
        string $encryptionKey
    ) {
        $this->userRepository = $userRepository;
        $this->idTokenBuilder = $idTokenBuilder;
        $this->privateKey = $privateKey;
        $this->encryptionKey = $encryptionKey;
    }

    public function build(): IdTokenResponse
    {
        $idTokenResponse = new IdTokenResponse(
            $this->userRepository,
            $this->idTokenBuilder,
            $this->privateKey
        );
        $idTokenResponse->setEncryptionKey($this->encryptionKey);

        return $idTokenResponse;
    }
}
