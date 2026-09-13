<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\ConfigurationError;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\FederationOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\GeneralOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\ProtocolOverviewBuilder;
use SimpleSAML\Module\oidc\Admin\ConfigOverview\VciOverviewBuilder;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\ConfigController;
use SimpleSAML\Module\oidc\Factories\FederationFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Services\DatabaseMigration;
use SimpleSAML\Module\oidc\Services\SessionMessagesService;
use SimpleSAML\Module\oidc\Utils\Routes;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Codebooks\WellKnownEnum;
use SimpleSAML\OpenID\Exceptions\FetchException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\EntityStatementFetcher;
use SimpleSAML\OpenID\Federation\Factories\TrustMarkFactory;
use SimpleSAML\OpenID\Federation\TrustMark;
use SimpleSAML\OpenID\Federation\TrustMarkFetcher;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Every configuration screen is built the same way: the screen's template, the module config together with
 * the sections its overview builder yields, and the screen's own route as the active menu item. The
 * federation screen also hands its builder the trust marks, read from two options which are guarded one by
 * one, and is the one screen which needs a Federation, which is why the controller takes the factory: a
 * Federation which cannot be built costs that screen its trust marks, not the screen, and not the controller.
 *
 * Template builds are captured whole and compared strictly, rather than pinned through with(): its
 * comparison is loose, so a null left to the factory would also accept false.
 */
#[CoversClass(ConfigController::class)]
#[AllowMockObjectsWithoutExpectations]
class ConfigControllerTest extends TestCase
{
    protected const string ISSUER = 'https://op.example.org';

    protected const string TRUST_MARK_ISSUER = 'https://trust-mark-issuer.example.org';

    protected const string FEDERATION_TEMPLATE = 'oidc:config/federation.twig';

    protected const array FEDERATION_SECTIONS = ['section' => 'federation'];

    protected const string FEDERATION_UNAVAILABLE_MESSAGE = 'Federation tooling could not be built from the ' .
    'current configuration, so trust marks are not shown. Check the federation options below, and the outbound ' .
    'destination policy on the Protocol configuration screen, which federation fetches also depend on.';

    protected const string TRUST_MARK_TOKENS_UNREADABLE_MESSAGE = 'Statically configured Trust Mark tokens could ' .
    'not be read, so they are not shown. Check that option below.';

    protected const string DYNAMIC_TRUST_MARKS_UNREADABLE_MESSAGE = 'Dynamically fetched Trust Marks could not be ' .
    'read, so they are not shown. Check that option below.';


    protected MockObject $moduleConfigMock;

    protected MockObject $templateFactoryMock;

    protected MockObject $authorizationMock;

    protected MockObject $databaseMigrationMock;

    protected MockObject $sessionMessagesServiceMock;

    protected MockObject $federationMock;

    protected MockObject $federationFactoryMock;

    protected MockObject $routesMock;

    protected MockObject $generalOverviewBuilderMock;

    protected MockObject $protocolOverviewBuilderMock;

    protected MockObject $federationOverviewBuilderMock;

    protected MockObject $vciOverviewBuilderMock;

    protected MockObject $trustMarkFactoryMock;

    protected MockObject $entityStatementFetcherMock;

    protected MockObject $trustMarkFetcherMock;

    protected Template $template;

    protected RedirectResponse $redirectResponse;

    /**
     * @var list<array<string, mixed>> Every template build, as its arguments by name, in order.
     */
    protected array $renderedTemplates;

    /**
     * @var string[] Every message added to the session, in order.
     */
    protected array $messages;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);

        $this->template = $this->createStub(Template::class);
        $this->renderedTemplates = [];
        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (
                string $templateName,
                array $data = [],
                ?string $activeHrefPath = null,
                ?bool $includeDefaultMenuItems = null,
                ?bool $showMenu = null,
                ?bool $showModuleName = null,
                ?bool $showSubPageTitle = null,
                ?string $language = null,
            ): Template {
                $this->renderedTemplates[] = compact(
                    'templateName',
                    'data',
                    'activeHrefPath',
                    'includeDefaultMenuItems',
                    'showMenu',
                    'showModuleName',
                    'showSubPageTitle',
                    'language',
                );
                return $this->template;
            },
        );

        $this->authorizationMock = $this->createMock(Authorization::class);
        $this->databaseMigrationMock = $this->createMock(DatabaseMigration::class);

        $this->messages = [];
        $this->sessionMessagesServiceMock = $this->createMock(SessionMessagesService::class);
        $this->sessionMessagesServiceMock->method('addMessage')->willReturnCallback(
            function (string $message): void {
                $this->messages[] = $message;
            },
        );

        $this->trustMarkFactoryMock = $this->createMock(TrustMarkFactory::class);
        $this->entityStatementFetcherMock = $this->createMock(EntityStatementFetcher::class);
        $this->trustMarkFetcherMock = $this->createMock(TrustMarkFetcher::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->federationMock->method('trustMarkFactory')->willReturn($this->trustMarkFactoryMock);
        $this->federationMock->method('entityStatementFetcher')->willReturn($this->entityStatementFetcherMock);
        $this->federationMock->method('trustMarkFetcher')->willReturn($this->trustMarkFetcherMock);
        $this->federationFactoryMock = $this->createMock(FederationFactory::class);
        $this->federationFactoryMock->method('build')->willReturn($this->federationMock);

        $this->redirectResponse = $this->createStub(RedirectResponse::class);
        $this->routesMock = $this->createMock(Routes::class);

        $this->generalOverviewBuilderMock = $this->createMock(GeneralOverviewBuilder::class);
        $this->protocolOverviewBuilderMock = $this->createMock(ProtocolOverviewBuilder::class);
        $this->federationOverviewBuilderMock = $this->createMock(FederationOverviewBuilder::class);
        $this->vciOverviewBuilderMock = $this->createMock(VciOverviewBuilder::class);
    }


    public function sut(
        ?ModuleConfig $moduleConfig = null,
        ?TemplateFactory $templateFactory = null,
        ?Authorization $authorization = null,
        ?DatabaseMigration $databaseMigration = null,
        ?SessionMessagesService $sessionMessagesService = null,
        ?FederationFactory $federationFactory = null,
        ?Routes $routes = null,
        ?GeneralOverviewBuilder $generalOverviewBuilder = null,
        ?ProtocolOverviewBuilder $protocolOverviewBuilder = null,
        ?FederationOverviewBuilder $federationOverviewBuilder = null,
        ?VciOverviewBuilder $vciOverviewBuilder = null,
    ): ConfigController {
        $moduleConfig ??= $this->moduleConfigMock;
        $templateFactory ??= $this->templateFactoryMock;
        $authorization ??= $this->authorizationMock;
        $databaseMigration ??= $this->databaseMigrationMock;
        $sessionMessagesService ??= $this->sessionMessagesServiceMock;
        $federationFactory ??= $this->federationFactoryMock;
        $routes ??= $this->routesMock;
        $generalOverviewBuilder ??= $this->generalOverviewBuilderMock;
        $protocolOverviewBuilder ??= $this->protocolOverviewBuilderMock;
        $federationOverviewBuilder ??= $this->federationOverviewBuilderMock;
        $vciOverviewBuilder ??= $this->vciOverviewBuilderMock;

        return new ConfigController(
            $moduleConfig,
            $templateFactory,
            $authorization,
            $databaseMigration,
            $sessionMessagesService,
            $federationFactory,
            $routes,
            $generalOverviewBuilder,
            $protocolOverviewBuilder,
            $federationOverviewBuilder,
            $vciOverviewBuilder,
        );
    }


    /**
     * The one template build so far: the given template with the given data, the given route as the active
     * menu item, and the default menu items, menu, module name, sub-page title and language left to the
     * factory.
     */
    protected function assertTemplateRendered(string $templateName, array $data, RoutesEnum $route): void
    {
        $this->assertSame(
            [
                [
                    'templateName' => $templateName,
                    'data' => $data,
                    'activeHrefPath' => $route->value,
                    'includeDefaultMenuItems' => null,
                    'showMenu' => null,
                    'showModuleName' => null,
                    'showSubPageTitle' => null,
                    'language' => null,
                ],
            ],
            $this->renderedTemplates,
        );
    }


    /**
     * A configuration screen: its template, the module config with the given sections, its route.
     */
    protected function assertScreenRendered(string $templateName, array $sections, RoutesEnum $route): void
    {
        $this->assertTemplateRendered(
            $templateName,
            ['moduleConfig' => $this->moduleConfigMock, 'sections' => $sections],
            $route,
        );
    }


    /**
     * The federation overview built from exactly these trust marks, in this order.
     */
    protected function expectFederationOverviewOf(array $trustMarks): void
    {
        $this->federationOverviewBuilderMock->expects($this->once())->method('build')
            ->with($this->identicalTo($trustMarks))
            ->willReturn(self::FEDERATION_SECTIONS);
    }


    protected function assertFederationScreenRendered(): void
    {
        $this->assertScreenRendered(
            self::FEDERATION_TEMPLATE,
            self::FEDERATION_SECTIONS,
            RoutesEnum::AdminConfigFederation,
        );
    }


    protected function expectNoDynamicTrustMarkFetched(): void
    {
        $this->entityStatementFetcherMock->expects($this->never())->method('fromCacheOrWellKnownEndpoint');
        $this->trustMarkFetcherMock->expects($this->never())->method('fromCacheOrFederationTrustMarkEndpoint');
    }


    protected function expectRedirectToTheMigrationsScreen(): void
    {
        $this->routesMock->expects($this->once())->method('newRedirectResponseToModuleUrl')
            ->with(RoutesEnum::AdminMigrations->value, [], 302, [])
            ->willReturn($this->redirectResponse);
    }


    /**
     * A statically configured trust mark: the token in the option, and the trust mark the factory parses from
     * it under the JWT type the factory defaults to.
     */
    protected function trustMarkFromToken(string $token): TrustMark
    {
        $trustMark = $this->createStub(TrustMark::class);
        $this->trustMarkFactoryMock->expects($this->once())->method('fromToken')
            ->with($token, JwtTypesEnum::TrustMarkJwt)
            ->willReturn($trustMark);

        return $trustMark;
    }


    /**
     * A dynamically fetched trust mark: the entity configuration of the issuer, from its well-known
     * endpoint, then the trust mark of the given type for this OP, from that configuration.
     */
    protected function trustMarkFetchedFor(string $trustMarkType, string $trustMarkIssuerId): TrustMark
    {
        $entityConfiguration = $this->createStub(EntityStatement::class);
        $this->entityStatementFetcherMock->expects($this->once())->method('fromCacheOrWellKnownEndpoint')
            ->with($trustMarkIssuerId, WellKnownEnum::OpenIdFederation, null)
            ->willReturn($entityConfiguration);

        $trustMark = $this->createStub(TrustMark::class);
        $this->trustMarkFetcherMock->expects($this->once())->method('fromCacheOrFederationTrustMarkEndpoint')
            ->with($trustMarkType, self::ISSUER, $this->identicalTo($entityConfiguration))
            ->willReturn($trustMark);

        return $trustMark;
    }


    public function testCanCreateInstance(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdmin')->with(true);

        $this->assertInstanceOf(ConfigController::class, $this->sut());
    }


    public function testCanShowMigrationsScreen(): void
    {
        $this->assertSame($this->template, $this->sut()->migrations());
        $this->assertTemplateRendered(
            'oidc:config/migrations.twig',
            ['databaseMigration' => $this->databaseMigrationMock],
            RoutesEnum::AdminMigrations,
        );
    }


    public function testRunsMigrationsAndRedirectsToTheMigrationsScreen(): void
    {
        $this->databaseMigrationMock->method('isMigrated')->willReturn(false);
        $this->databaseMigrationMock->expects($this->once())->method('migrate');
        $this->expectRedirectToTheMigrationsScreen();

        $this->assertSame($this->redirectResponse, $this->sut()->runMigrations());
        $this->assertSame(['Database migrated successfully.'], $this->messages);
    }


    public function testWontRunMigrationsIfAlreadyMigrated(): void
    {
        $this->databaseMigrationMock->method('isMigrated')->willReturn(true);
        $this->databaseMigrationMock->expects($this->never())->method('migrate');
        $this->expectRedirectToTheMigrationsScreen();

        $this->assertSame($this->redirectResponse, $this->sut()->runMigrations());
        $this->assertSame(['Database is already migrated.'], $this->messages);
    }


    public function testCanShowGeneralSettingsScreen(): void
    {
        $sections = ['section' => 'general'];
        $this->generalOverviewBuilderMock->expects($this->once())->method('build')->willReturn($sections);

        $this->assertSame($this->template, $this->sut()->generalSettings());
        $this->assertScreenRendered('oidc:config/general.twig', $sections, RoutesEnum::AdminConfigGeneral);
    }


    public function testCanShowProtocolSettingsScreen(): void
    {
        $sections = ['section' => 'protocol'];
        $this->protocolOverviewBuilderMock->expects($this->once())->method('build')->willReturn($sections);

        $this->assertSame($this->template, $this->sut()->protocolSettings());
        $this->assertScreenRendered('oidc:config/protocol.twig', $sections, RoutesEnum::AdminConfigProtocol);
    }


    public function testCanShowVerifiableCredentialSettingsScreen(): void
    {
        $sections = ['section' => 'verifiable credential'];
        $this->vciOverviewBuilderMock->expects($this->once())->method('build')->willReturn($sections);

        $this->assertSame($this->template, $this->sut()->verifiableCredentialSettings());
        $this->assertScreenRendered(
            'oidc:config/verifiable-credential.twig',
            $sections,
            RoutesEnum::AdminConfigVerifiableCredential,
        );
    }


    public function testCanShowFederationSettingsScreenWithoutTrustMarks(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')->willReturn(null);
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')->willReturn(null);
        $this->trustMarkFactoryMock->expects($this->never())->method('fromToken');
        $this->expectNoDynamicTrustMarkFetched();
        $this->expectFederationOverviewOf([]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([], $this->messages);
    }


    public function testCanIncludeTrustMarksInFederationSettings(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')->willReturn(['token']);
        $trustMark = $this->trustMarkFromToken('token');
        $this->expectNoDynamicTrustMarkFetched();
        $this->expectFederationOverviewOf([$trustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([], $this->messages);
    }


    public function testCanIncludeDynamicTrustMarksInFederationSettings(): void
    {
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willReturn(['trust-mark-type' => self::TRUST_MARK_ISSUER]);
        $this->trustMarkFactoryMock->expects($this->never())->method('fromToken');
        $trustMark = $this->trustMarkFetchedFor('trust-mark-type', self::TRUST_MARK_ISSUER);
        $this->expectFederationOverviewOf([$trustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([], $this->messages);
    }


    public function testShowsTheStaticTrustMarksAheadOfTheDynamicOnes(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')->willReturn(['token']);
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willReturn(['trust-mark-type' => self::TRUST_MARK_ISSUER]);
        $staticTrustMark = $this->trustMarkFromToken('token');
        $dynamicTrustMark = $this->trustMarkFetchedFor('trust-mark-type', self::TRUST_MARK_ISSUER);
        $this->expectFederationOverviewOf([$staticTrustMark, $dynamicTrustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([], $this->messages);
    }


    /**
     * The one screen needing a Federation gets by without one: a message in place of the trust marks, and the
     * screen with none. The exception message is not shown, since it can quote configured values back, and
     * the trust mark options are not read, having no Federation to serve.
     */
    public function testSurvivesAFederationWhichCannotBeBuilt(): void
    {
        $federationFactory = $this->createMock(FederationFactory::class);
        $federationFactory->method('build')
            ->willThrowException(new ConfigurationError('Outbound policy allows nothing.'));
        $this->moduleConfigMock->expects($this->never())->method('getFederationTrustMarkTokens');
        $this->moduleConfigMock->expects($this->never())->method('getFederationDynamicTrustMarks');
        $this->expectFederationOverviewOf([]);

        $this->assertSame(
            $this->template,
            $this->sut(federationFactory: $federationFactory)->federationSettings(),
        );
        $this->assertFederationScreenRendered();
        $this->assertSame([self::FEDERATION_UNAVAILABLE_MESSAGE], $this->messages);
    }


    /**
     * A dynamic trust mark which cannot be fetched is reported as two messages, the translatable sentence and
     * the untranslatable detail, and costs only itself: the marks after it are still fetched and shown.
     */
    public function testReportsADynamicTrustMarkWhichCannotBeFetchedAndKeepsTheOthers(): void
    {
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')->willReturn([
            'unreachable-type' => 'https://unreachable.example.org',
            'trust-mark-type' => self::TRUST_MARK_ISSUER,
        ]);
        $reachableEntityConfiguration = $this->createStub(EntityStatement::class);
        $entityConfigurationFetches = [];
        $this->entityStatementFetcherMock->method('fromCacheOrWellKnownEndpoint')->willReturnCallback(
            function (
                string $entityId,
                WellKnownEnum $wellKnownEnum,
                ?float $deadlineTimestamp,
            ) use (
                &$entityConfigurationFetches,
                $reachableEntityConfiguration,
            ): EntityStatement {
                $entityConfigurationFetches[] = [$entityId, $wellKnownEnum, $deadlineTimestamp];
                if ($entityId === 'https://unreachable.example.org') {
                    throw new FetchException('Could not fetch.');
                }
                return $reachableEntityConfiguration;
            },
        );
        $trustMark = $this->createStub(TrustMark::class);
        $this->trustMarkFetcherMock->expects($this->once())->method('fromCacheOrFederationTrustMarkEndpoint')
            ->with('trust-mark-type', self::ISSUER, $this->identicalTo($reachableEntityConfiguration))
            ->willReturn($trustMark);
        $this->expectFederationOverviewOf([$trustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame(
            [
                ['https://unreachable.example.org', WellKnownEnum::OpenIdFederation, null],
                [self::TRUST_MARK_ISSUER, WellKnownEnum::OpenIdFederation, null],
            ],
            $entityConfigurationFetches,
        );
        $this->assertSame(
            [
                'Error fetching dynamic trust mark:',
                'trust_mark_type => unreachable-type, issuer_id => https://unreachable.example.org. Could not fetch.',
            ],
            $this->messages,
        );
    }


    /**
     * These two options are read here rather than by a builder, so their guarded rows cannot protect them: a
     * wrong top-level type threw on the way to the screen and returned a 500 from the one page able to
     * explain it. Each read is guarded on its own, so that the broken option does not hide the marks the
     * other one yields: one catch around both would skip the second read when the first threw, hiding
     * readable marks, and when the second threw would report that nothing is shown next to marks the first
     * read had already produced.
     */
    public function testAMalformedTrustMarkTokensOptionDoesNotHideTheDynamicTrustMarks(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')
            ->willThrowException(new ConfigurationError('Not an array.'));
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willReturn(['trust-mark-type' => self::TRUST_MARK_ISSUER]);
        $this->trustMarkFactoryMock->expects($this->never())->method('fromToken');
        $trustMark = $this->trustMarkFetchedFor('trust-mark-type', self::TRUST_MARK_ISSUER);
        $this->expectFederationOverviewOf([$trustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([self::TRUST_MARK_TOKENS_UNREADABLE_MESSAGE], $this->messages);
    }


    /**
     * The other way round: the second read is behind the first, so a failure there is caught just the same,
     * and the statically configured marks the first read produced are shown.
     */
    public function testAMalformedDynamicTrustMarksOptionDoesNotHideTheTrustMarkTokens(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')->willReturn(['token']);
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willThrowException(new ConfigurationError('Not an array.'));
        $trustMark = $this->trustMarkFromToken('token');
        $this->expectNoDynamicTrustMarkFetched();
        $this->expectFederationOverviewOf([$trustMark]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame([self::DYNAMIC_TRUST_MARKS_UNREADABLE_MESSAGE], $this->messages);
    }


    public function testReportsBothMalformedTrustMarkOptionsAndStillShowsTheScreen(): void
    {
        $this->moduleConfigMock->method('getFederationTrustMarkTokens')
            ->willThrowException(new ConfigurationError('Not an array.'));
        $this->moduleConfigMock->method('getFederationDynamicTrustMarks')
            ->willThrowException(new ConfigurationError('Not an array.'));
        $this->trustMarkFactoryMock->expects($this->never())->method('fromToken');
        $this->expectNoDynamicTrustMarkFetched();
        $this->expectFederationOverviewOf([]);

        $this->assertSame($this->template, $this->sut()->federationSettings());
        $this->assertFederationScreenRendered();
        $this->assertSame(
            [self::TRUST_MARK_TOKENS_UNREADABLE_MESSAGE, self::DYNAMIC_TRUST_MARKS_UNREADABLE_MESSAGE],
            $this->messages,
        );
    }
}
