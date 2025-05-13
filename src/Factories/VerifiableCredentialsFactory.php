<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Factories;

use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\OpenID\VerifiableCredentials;

class VerifiableCredentialsFactory
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly LoggerService $loggerService,
    ) {
    }

    /**
     * @throws \ReflectionException
     * @throws \SimpleSAML\Error\ConfigurationError
     */
    public function build(): VerifiableCredentials
    {
        $supportedAlgorithms = new SupportedAlgorithms(
            new SignatureAlgorithmBag(
                SignatureAlgorithmEnum::from($this->moduleConfig->getProtocolSigner()->algorithmId()),
                SignatureAlgorithmEnum::RS384,
                SignatureAlgorithmEnum::RS512,
                SignatureAlgorithmEnum::ES256,
                SignatureAlgorithmEnum::ES384,
                SignatureAlgorithmEnum::ES512,
                SignatureAlgorithmEnum::PS256,
                SignatureAlgorithmEnum::PS384,
                SignatureAlgorithmEnum::PS512,
            ),
        );

        return new VerifiableCredentials(
            supportedAlgorithms: $supportedAlgorithms,
            logger: $this->loggerService,
        );
    }
}
