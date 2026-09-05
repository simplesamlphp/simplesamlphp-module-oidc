<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Admin\ConfigOverview;

use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Repositories\StatusListRepository;
use SimpleSAML\Module\oidc\Repositories\VciIssuerIdentityRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\DateIntervalFormatter;
use SimpleSAML\Module\oidc\Utils\Routes;
use Throwable;

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
     * @param string[]|\Throwable $statusListIssuerIdentifiers The did:web identifiers the Status Lists
     *                                                         which are still served were created
     *                                                         under, or what reading them throws.
     * @param array<string,string> $routeUrls Route method name to the URL it should return. Every
     *                                        endpoint row is built the same way from this one
     *                                        Routes instance, so distinct URLs are what lets a
     *                                        test tell one endpoint row from another. Does not
     *                                        cover urlVciDidDocument, which has its own
     *                                        parameter above.
     * @throws \Exception
     */
    protected function buildVciOverviewBuilder(
        array $overrides = [],
        array $usedIssuerIdentities = [],
        ?string $didDocumentUrl = null,
        array|Throwable $statusListIssuerIdentifiers = [],
        array $routeUrls = [],
    ): VciOverviewBuilder {
        $vciIssuerIdentityRepository = $this->createMock(VciIssuerIdentityRepository::class);
        $vciIssuerIdentityRepository->method('getAllUsed')->willReturn($usedIssuerIdentities);

        $statusListRepository = $this->createMock(StatusListRepository::class);
        $getUnretiredIssuerIdentifiers = $statusListRepository->method('getUnretiredIssuerIdentifiers');

        if ($statusListIssuerIdentifiers instanceof Throwable) {
            $getUnretiredIssuerIdentifiers->willThrowException($statusListIssuerIdentifiers);
        } else {
            $getUnretiredIssuerIdentifiers->willReturn($statusListIssuerIdentifiers);
        }

        $routes = $this->createMock(Routes::class);
        $routes->method('urlVciDidDocument')->willReturn($didDocumentUrl ?? '');

        foreach ($routeUrls as $routeMethod => $url) {
            $routes->method($routeMethod)->willReturn($url);
        }

        return new VciOverviewBuilder(
            $this->buildOverviewModuleConfig($overrides),
            $routes,
            new DateIntervalFormatter(),
            $this->createMock(LoggerService::class),
            $vciIssuerIdentityRepository,
            $statusListRepository,
        );
    }
}
