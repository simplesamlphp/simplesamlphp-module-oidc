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

class FederationTestController
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


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function federationDiscovery(Request $request): Response
    {
        $trustAnchorId = null;
        $isFormSubmitted = false;
        $entities = [];
        $forceRefresh = false;
        $filterEntityTypes = [];
        $filterTrustMarkTypes = '';
        $filterQuery = '';
        $sortBy = 'entity_id';
        $sortOrder = 'asc';
        $pageLimit = 50;
        $pageFrom = null;
        $nextPageToken = null;
        $totalCount = 0;

        if ($request->isMethod(Request::METHOD_POST)) {
            $isFormSubmitted = true;

            !empty($trustAnchorId = $request->request->getString('trustAnchorId')) ||
            throw new OidcException('Empty Trust Anchor ID.');

            $forceRefresh = $request->request->getBoolean('forceRefresh');
            /** @var string[] $filterEntityTypes */
            $filterEntityTypes = $request->request->all('filterEntityTypes');
            $filterTrustMarkTypes = $request->request->getString('filterTrustMarkTypes');
            $filterQuery = $request->request->getString('filterQuery');
            $sortBy = $request->request->getString('sortBy', 'entity_id');
            $sortOrder = $request->request->getString('sortOrder', 'asc');
            /** @var 'asc'|'desc' $sortOrder */
            $sortOrder = in_array($sortOrder, ['asc', 'desc']) ? $sortOrder : 'asc';
            $pageLimit = $request->request->getInt('pageLimit', 50);
            $pageFrom = $request->request->get('pageFrom');
            $pageFrom = is_string($pageFrom) ? $pageFrom : null;

            try {
                $entityCollection = $this->federationWithArrayLogger->federationDiscovery()->discover(
                    trustAnchorId: $trustAnchorId,
                    forceRefresh: $forceRefresh,
                );

                // 1. Filtering
                $criteria = array_filter([
                    'entity_type' => $filterEntityTypes,
                    'trust_mark_type' => $this->helpers->str()->convertTextToArray($filterTrustMarkTypes),
                    'query' => $filterQuery,
                ]);
                if (!empty($criteria)) {
                    $entityCollection->filter($criteria);
                }

                $totalCount = count($entityCollection->getEntities());

                // 2. Sorting
                $claimPaths = match ($sortBy) {
                    'display_name' => [
                        ['metadata', EntityTypesEnum::OpenIdProvider->value, 'display_name'],
                        ['metadata', EntityTypesEnum::FederationEntity->value, 'display_name'],
                        ['metadata', EntityTypesEnum::OpenIdRelyingParty->value, 'display_name'],
                    ],
                    'organization_name' => [
                        ['metadata', EntityTypesEnum::OpenIdProvider->value, 'organization_name'],
                        ['metadata', EntityTypesEnum::FederationEntity->value, 'organization_name'],
                        ['metadata', EntityTypesEnum::OpenIdRelyingParty->value, 'organization_name'],
                    ],
                    default => [['sub']],
                };
                $entityCollection->sort($claimPaths, $sortOrder);

                // 3. Pagination
                /** @var positive-int $pageLimit */
                $entityCollection->paginate($pageLimit, $pageFrom);

                $nextPageToken = $entityCollection->getNextPageToken();

                foreach ($entityCollection->getEntities() as $id => $payload) {
                    $entities[] = [
                        'id' => $id,
                        'payload' => $payload,
                    ];
                }
            } catch (\Throwable $exception) {
                $this->arrayLogger->error(sprintf(
                    'Error during entity discovery under Trust Anchor %s. Error was %s',
                    $trustAnchorId,
                    $exception->getMessage(),
                ));
            }
        }

        $logMessages = $this->arrayLogger->getEntries();

        try {
            $trustAnchorIds = $this->moduleConfig->getFederationTrustAnchorIds();
        } catch (\Throwable $exception) {
            $this->arrayLogger->error('Module config error: ' . $exception->getMessage());
            $trustAnchorIds = [];
        }

        $entityTypeOptions = array_map(fn (EntityTypesEnum $enum) => $enum->value, EntityTypesEnum::cases());

        return $this->templateFactory->build(
            'oidc:tests/federation-discovery.twig',
            compact(
                'trustAnchorId',
                'logMessages',
                'isFormSubmitted',
                'entities',
                'trustAnchorIds',
                'forceRefresh',
                'filterEntityTypes',
                'filterTrustMarkTypes',
                'filterQuery',
                'sortBy',
                'sortOrder',
                'pageLimit',
                'pageFrom',
                'nextPageToken',
                'totalCount',
                'entityTypeOptions',
            ),
            RoutesEnum::AdminTestFederationDiscovery->value,
        );
    }
}
