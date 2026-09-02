<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;

/**
 * Builds a VciOverviewBuilder for tests. Requires OverviewTestTrait.
 */
trait VciOverviewTestTrait
{
    /**
     * @param array $overrides Module config option overrides.
     * @param array<string,string> $usedIssuerIdentities Identifier to the mode it was issued under.
     * @param ?string $didDocumentUrl Where this module serves its DID document, which the configured
     *                                did:web identifier has to resolve to.
     * @throws \Exception
     */
    protected function buildVciOverviewBuilder(
        array $overrides = [],
        array $usedIssuerIdentities = [],
        ?string $didDocumentUrl = null,
    ): VciOverviewBuilder {
        $vciIssuerIdentityRepository = $this->createMock(VciIssuerIdentityRepository::class);
        $vciIssuerIdentityRepository->method('getAllUsed')->willReturn($usedIssuerIdentities);

        $routes = $this->createMock(Routes::class);
        $routes->method('urlVciDidDocument')->willReturn($didDocumentUrl ?? '');

        return new VciOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $routes,
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
            $vciIssuerIdentityRepository,
        );
    }
}
