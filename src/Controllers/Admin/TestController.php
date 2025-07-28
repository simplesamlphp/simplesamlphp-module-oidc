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
    protected readonly Federation $federationWithArrayLogger;

    public function __construct(
        protected readonly ModuleConfig $moduleConfig,
        protected readonly TemplateFactory $templateFactory,
        protected readonly Authorization $authorization,
        protected readonly Federation $federation,
        protected readonly Helpers $helpers,
        protected readonly ArrayLogger $arrayLogger,
    ) {
        $this->authorization->requireAdmin(true);

        $this->arrayLogger->setWeight(ArrayLogger::WEIGHT_WARNING);
        // Let's create a new Federation instance so we can inject our debug logger and go without cache.
        $this->federationWithArrayLogger = new Federation(
            supportedAlgorithms: $this->federation->supportedAlgorithms(),
            cache: null,
            logger: $this->arrayLogger,
        );
    }

    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function trustChainResolution(Request $request): Response
    {
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
                $trustChainBag = $this->federationWithArrayLogger->trustChainResolver()
                    ->for($leafEntityId, $trustAnchorIds);

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

    public function trustMarkValidation(Request $request): Response
    {
        $trustMarkType = null;
        $leafEntityId = null;
        $trustAnchorId = null;
        $isFormSubmitted = false;

        if ($request->isMethod(Request::METHOD_POST)) {
            $isFormSubmitted = true;

            !empty($trustMarkType = $request->request->getString('trustMarkType')) ||
            throw new OidcException('Empty Trust Mark Type.');
            !empty($leafEntityId = $request->request->getString('leafEntityId')) ||
            throw new OidcException('Empty leaf entity ID.');
            !empty($trustAnchorId = $request->request->getString('trustAnchorId')) ||
            throw new OidcException('Empty Trust Anchor ID.');

            try {
                // We should not try to validate Trust Marks until we have resolved a trust chain between leaf and TA.
                $trustChain = $this->federation->trustChainResolver()->for(
                    $leafEntityId,
                    [$trustAnchorId],
                )->getShortest();

                try {
                    $this->federationWithArrayLogger->trustMarkValidator()->doForTrustMarkType(
                        $trustMarkType,
                        $trustChain->getResolvedLeaf(),
                        $trustChain->getResolvedTrustAnchor(),
                    );
                } catch (\Throwable $exception) {
                    $this->arrayLogger->error('Trust Mark validation error: ' . $exception->getMessage());
                }
            } catch (TrustChainException $exception) {
                $this->arrayLogger->error(sprintf(
                    'Could not resolve Trust Chain for leaf entity %s under Trust Anchor %s. Error was %s',
                    $leafEntityId,
                    $trustAnchorId,
                    $exception->getMessage(),
                ));
            }
        }

        $logMessages = $this->arrayLogger->getEntries();

        return $this->templateFactory->build(
            'oidc:tests/trust-mark-validation.twig',
            compact(
                'trustMarkType',
                'leafEntityId',
                'trustAnchorId',
                'logMessages',
                'isFormSubmitted',
            ),
            RoutesEnum::AdminTestTrustMarkValidation->value,
        );
    }
}
