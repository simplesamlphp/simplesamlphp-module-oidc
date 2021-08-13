<?php

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

namespace SimpleSAML\Modules\OpenIDConnect\Factories;

use League\OAuth2\Server\CryptKey;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository;
use SimpleSAML\Modules\OpenIDConnect\Server\ResponseTypes\IdTokenResponse;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;
use SimpleSAML\Modules\OpenIDConnect\Services\IdTokenBuilder;
use SimpleSAML\Modules\OpenIDConnect\Services\RequestedClaimsEncoderService;
use SimpleSAML\Utils\Config;

class IdTokenBuilderFactory
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Repositories\UserRepository
     */
    private $userRepository;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService
     */
    private $configurationService;

    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor
     */
    private $claimTranslatorExtractor;
    /**
     * @var CryptKey
     */
    private $privateKey;

    /**
     * @var RequestedClaimsEncoderService
     */
    private $requestedClaimsEncoderService;

    public function __construct(
        UserRepository $userRepository,
        ConfigurationService $configurationService,
        ClaimTranslatorExtractor $claimTranslatorExtractor,
        CryptKey $privateKey,
        RequestedClaimsEncoderService $requestedClaimsEncoderService
    ) {
        $this->userRepository = $userRepository;
        $this->configurationService = $configurationService;
        $this->claimTranslatorExtractor = $claimTranslatorExtractor;
        $this->privateKey = $privateKey;
        $this->requestedClaimsEncoderService = $requestedClaimsEncoderService;
    }

    public function build(): IdTokenBuilder
    {
        return new IdTokenBuilder(
            $this->userRepository,
            $this->claimTranslatorExtractor,
            $this->configurationService,
            $this->privateKey,
            $this->requestedClaimsEncoderService
        );
    }
}
