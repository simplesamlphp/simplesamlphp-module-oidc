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

use OpenIDConnectServer\Entities\ClaimSetEntity;
use SimpleSAML\Modules\OpenIDConnect\ClaimTranslatorExtractor;
use SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService;

class ClaimTranslatorExtractorFactory
{
    /**
     * @var \SimpleSAML\Modules\OpenIDConnect\Services\ConfigurationService
     */
    private $configurationService;

    public function __construct(
        ConfigurationService $configurationService
    ) {
        $this->configurationService = $configurationService;
    }

    public function build(): ClaimTranslatorExtractor
    {
        $translatorTable = $this->configurationService->getOpenIDConnectConfiguration()->getArray('translate', []);

        $scopes = $this->configurationService->getOpenIDPrivateScopes();
        $scopes = array_map(
            /**
             * @param array<array<string>> $config
             *
             * @return \OpenIDConnectServer\Entities\ClaimSetEntity
             */
            function (array $config, string $scope) {
                return new ClaimSetEntity($scope, $config['attributes'] ?? []);
            },
            $scopes,
            array_keys($scopes)
        );

        return new ClaimTranslatorExtractor($scopes, $translatorTable);
    }
}
