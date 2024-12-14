<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidc\Controllers\Admin;

use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Debug\ArrayLogger;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\TrustChainException;
use SimpleSAML\OpenID\Federation;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class TestController
{
    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly Federation $federation,
        protected readonly Helpers $helpers,
        protected readonly ArrayLogger $arrayLogger,
    ) {
        $this->authorization->requireAdmin(true);
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function trustChainResolution(Request $request): Response
    {
        $this->arrayLogger->setWeight(ArrayLogger::WEIGHT_WARNING);
        // Let's create new Federation instance so we can inject our debug logger and go without cache.
        $federation = new Federation(
            supportedAlgorithms: $this->federation->supportedAlgorithms(),
            cache: null,
            logger: $this->arrayLogger,
        );

        $leafEntityId = $this->moduleConfig->getIssuer();
        $trustChainBag = null;
        $resolvedMetadata = [];
        $isFormSubmitted = false;

        try {
            $trustAnchorIds = $this->moduleConfig->getFederationTrustAnchorIds();
        } catch (\Throwable $exception) {
            $this->arrayLogger->error('Module config error: ' . $exception->getMessage());
            $trustAnchorIds = [];
        }

        if ($request->isMethod(Request::METHOD_POST)) {
            $isFormSubmitted = true;

            !empty($leafEntityId = $request->request->getString('leafEntityId')) ||
                throw new OidcException('Empty leaf entity ID.');
            !empty($rawTrustAnchorIds = $request->request->getString('trustAnchorIds')) ||
                throw new OidcException('Empty Trust Anchor IDs.');

            /** @var non-empty-array<non-empty-string> $trustAnchorIds */
            $trustAnchorIds = $this->helpers->str()->convertTextToArray($rawTrustAnchorIds);

            try {
                $trustChainBag = $federation->trustChainResolver()->for($leafEntityId, $trustAnchorIds);

                foreach ($trustChainBag->getAll() as $index => $trustChain) {
                    $metadataEntries = [];
                    foreach (EntityTypesEnum::cases() as $entityTypeEnum) {
                        try {
                            $metadataEntries[$entityTypeEnum->value] =
                                $trustChain->getResolvedMetadata($entityTypeEnum);
                        } catch (\Throwable $exception) {
                            $this->arrayLogger->error(
                                'Metadata resolving error: ' . $exception->getMessage(),
                                compact('index', 'entityTypeEnum'),
                            );
                            continue;
                        }
                    }
                    $resolvedMetadata[$index] = array_filter($metadataEntries);
                }
            } catch (TrustChainException $exception) {
                $this->arrayLogger->error('Trust chain error: ' . $exception->getMessage());
            }
        }

        $trustAnchorIds = implode("\n", $trustAnchorIds);
        $logMessages = $this->arrayLogger->getEntries();
//dd($this->arrayLogger->getEntries());
        return $this->templateFactory->build(
            'oidc:tests/trust-chain-resolution.twig',
            compact(
                'leafEntityId',
                'trustAnchorIds',
                'trustChainBag',
                'resolvedMetadata',
                'logMessages',
                'isFormSubmitted',
            ),
            RoutesEnum::AdminTestTrustChainResolution->value,
        );
    }
}
