<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Controllers\Admin;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\Create;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use SimpleSAML\Module\oidc\Admin\Authorization;
use SimpleSAML\Module\oidc\Codebooks\RoutesEnum;
use SimpleSAML\Module\oidc\Controllers\Admin\FederationTestController;
use SimpleSAML\Module\oidc\Exceptions\OidcException;
use SimpleSAML\Module\oidc\Factories\DestinationPolicyFactory;
use SimpleSAML\Module\oidc\Factories\TemplateFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Utils\Debug\ArrayLogger;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\TrustChainException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\Federation\TrustChainBag;
use SimpleSAML\OpenID\Federation\TrustChainResolver;
use SimpleSAML\OpenID\Network\DestinationGuardMiddleware;
use SimpleSAML\OpenID\Network\DestinationPolicy;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * The controller builds a `Federation` of its own in its constructor, so that the page reports what the
 * protocol endpoints would actually do rather than what a cached or unlogged resolution did. That object
 * can not be replaced from here, which is why these tests hold the transport still instead: the HTTP
 * client is configured with a handler which refuses every request, so nothing reaches the network and a
 * resolution always fails the same way. What that leaves untestable from here is noted on the tests
 * themselves.
 */
#[CoversClass(FederationTestController::class)]
#[AllowMockObjectsWithoutExpectations]
class FederationTestControllerTest extends TestCase
{
    protected const string ISSUER = 'https://op.example.org';

    protected const string LEAF_ENTITY_ID = 'https://leaf.example.org';

    protected const string TRUST_ANCHOR_ID = 'https://ta.example.org';

    protected const string TRUST_MARK_TYPE = 'https://ta.example.org/trust-mark/member';


    protected MockObject $moduleConfigMock;

    protected MockObject $templateFactoryMock;

    protected MockObject $authorizationMock;

    protected MockObject $federationMock;

    protected MockObject $trustChainResolverMock;

    protected MockObject $destinationPolicyFactoryMock;

    protected Helpers $helpers;

    protected ArrayLogger $arrayLogger;

    /** @var array<string,mixed> The data the controller handed the template. */
    protected array $templateData = [];

    /** @var string[] */
    protected array $trustAnchorIds = [self::TRUST_ANCHOR_ID];

    /** Thrown by the module configuration when it is asked for the Trust Anchors. */
    protected ?Throwable $trustAnchorIdsError = null;

    /** Thrown by the injected federation's resolver, which only the Trust Mark page uses. */
    protected ?Throwable $trustChainError = null;


    protected function setUp(): void
    {
        $this->templateData = [];
        $this->trustAnchorIds = [self::TRUST_ANCHOR_ID];
        $this->trustAnchorIdsError = null;
        $this->trustChainError = null;

        $this->helpers = new Helpers();
        $this->arrayLogger = new ArrayLogger($this->helpers);

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getIssuer')->willReturn(self::ISSUER);
        $this->moduleConfigMock->method('getFederationTrustAnchorIds')->willReturnCallback(
            function (): array {
                if ($this->trustAnchorIdsError !== null) {
                    throw $this->trustAnchorIdsError;
                }

                return $this->trustAnchorIds;
            },
        );
        $this->moduleConfigMock->method('getFederationMaxTrustChainDepth')->willReturn(9);
        $this->moduleConfigMock->method('getFederationMaxAuthorityHints')->willReturn(6);
        $this->moduleConfigMock->method('getFederationMaxTrustChainFetches')->willReturn(100);
        $this->moduleConfigMock->method('getFederationTrustChainResolveTimeout')->willReturn(30);
        $this->moduleConfigMock->method('getFederationMaxFetchSizeBytes')->willReturn(512 * 1024);
        // Nothing this page does may reach the network from a test, so the client is given a handler which
        // refuses every request. A resolution then fails the way an unreachable entity would.
        $this->moduleConfigMock->method('getFederationHttpClientOptions')->willReturn([
            'handler' => static fn(RequestInterface $request, array $options) => Create::rejectionFor(
                new ConnectException('Connection refused (test).', $request),
            ),
        ]);

        $this->authorizationMock = $this->createMock(Authorization::class);

        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (string $templateName, array $data = []): Template {
                $this->templateData = $data;

                return $this->createMock(Template::class);
            },
        );

        $this->trustChainResolverMock = $this->createMock(TrustChainResolver::class);
        $this->trustChainResolverMock->method('for')->willReturnCallback(
            function (): TrustChainBag {
                if ($this->trustChainError !== null) {
                    throw $this->trustChainError;
                }

                $trustChainBag = $this->createMock(TrustChainBag::class);
                $trustChainBag->method('getShortest')->willReturn($this->createMock(TrustChain::class));

                return $trustChainBag;
            },
        );

        $this->federationMock = $this->createMock(Federation::class);
        $this->federationMock->method('supportedAlgorithms')->willReturn(new SupportedAlgorithms());
        $this->federationMock->method('trustChainResolver')->willReturn($this->trustChainResolverMock);

        // A pass-through guard: where outbound requests may be sent is DestinationPolicy's own subject, and
        // a real one would resolve the host names these tests use.
        $guardMock = $this->createMock(DestinationGuardMiddleware::class);
        $guardMock->method('__invoke')->willReturnCallback(
            static fn(callable $handler): callable => $handler,
        );
        $destinationPolicyMock = $this->createMock(DestinationPolicy::class);
        $destinationPolicyMock->method('middleware')->willReturn($guardMock);
        $this->destinationPolicyFactoryMock = $this->createMock(DestinationPolicyFactory::class);
        $this->destinationPolicyFactoryMock->method('build')->willReturn($destinationPolicyMock);
    }


    protected function sut(): FederationTestController
    {
        return new FederationTestController(
            $this->moduleConfigMock,
            $this->templateFactoryMock,
            $this->authorizationMock,
            $this->federationMock,
            $this->helpers,
            $this->arrayLogger,
            $this->destinationPolicyFactoryMock,
        );
    }


    /**
     * @param array<string,mixed> $body
     */
    protected function request(array $body = []): Request
    {
        $request = new Request([], $body);
        $request->setMethod($body === [] ? Request::METHOD_GET : Request::METHOD_POST);

        return $request;
    }


    /**
     * These pages resolve trust chains and fetch from remote entities on demand, so they are for an
     * administrator - and the check runs in the constructor, where the container reaches it.
     */
    public function testRequiresAnAdministrator(): void
    {
        $this->authorizationMock->expects($this->once())->method('requireAdmin')->with(true);

        $this->sut();
    }


    /**
     * The page reports what the protocol endpoints would do, so it resolves under the deployment's own
     * traversal limits rather than the library defaults - and through its outbound destination policy,
     * without which this page could reach destinations those endpoints refuse.
     */
    public function testResolvesUnderTheDeploymentsOwnLimitsAndDestinationPolicy(): void
    {
        $this->moduleConfigMock->expects($this->once())->method('getFederationMaxTrustChainDepth')
            ->willReturn(9);
        $this->moduleConfigMock->expects($this->once())->method('getFederationMaxAuthorityHints')
            ->willReturn(6);
        $this->moduleConfigMock->expects($this->once())->method('getFederationMaxTrustChainFetches')
            ->willReturn(100);
        $this->moduleConfigMock->expects($this->once())->method('getFederationTrustChainResolveTimeout')
            ->willReturn(30);
        $this->moduleConfigMock->expects($this->once())->method('getFederationMaxFetchSizeBytes')
            ->willReturn(512 * 1024);
        $this->destinationPolicyFactoryMock->expects($this->once())->method('build');

        $this->sut();
    }


    /**
     * Warnings and above, so that a resolution which succeeded but complained still says so.
     */
    public function testReportsWarningsAndAbove(): void
    {
        $this->sut();

        $this->arrayLogger->warning('A warning.');
        $this->arrayLogger->debug('A debug message.');

        $entries = $this->arrayLogger->getEntries();

        $this->assertCount(1, $entries);
        $this->assertStringContainsString('A warning.', $entries[0]);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testTrustChainResolutionRendersTheFormBeforeItIsSubmitted(): void
    {
        $this->trustAnchorIds = [self::TRUST_ANCHOR_ID, 'https://ta2.example.org'];

        $this->sut()->trustChainResolution($this->request());

        $this->assertFalse($this->templateData['isFormSubmitted'] ?? null);
        // This deployment is the leaf whose chain an administrator most likely wants to resolve.
        $this->assertSame(self::ISSUER, $this->templateData['leafEntityId'] ?? null);
        // One per line, because that is how the form takes them back.
        $this->assertSame(
            self::TRUST_ANCHOR_ID . "\nhttps://ta2.example.org",
            $this->templateData['trustAnchorIds'] ?? null,
        );
        $this->assertArrayHasKey('trustChainBag', $this->templateData);
        $this->assertNull($this->templateData['trustChainBag']);
        $this->assertSame([], $this->templateData['resolvedMetadata'] ?? null);
    }


    /**
     * A configuration this page can not read is the very thing an administrator opened it to find out
     * about, so it is reported on the page rather than raised as an error.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testTrustChainResolutionReportsAConfigurationItCanNotRead(): void
    {
        $this->trustAnchorIdsError = new RuntimeException('Trust Anchors are malformed.');

        $this->sut()->trustChainResolution($this->request());

        $this->assertStringContainsString(
            'Trust Anchors are malformed.',
            implode("\n", (array)($this->templateData['logMessages'] ?? [])),
        );
        $this->assertSame('', $this->templateData['trustAnchorIds'] ?? null);
    }


    /**
     * @param array<string,mixed> $body
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    #[DataProvider('incompleteTrustChainResolutionFormProvider')]
    public function testTrustChainResolutionRefusesAnIncompleteForm(array $body): void
    {
        $this->expectException(OidcException::class);

        $this->sut()->trustChainResolution($this->request($body));
    }


    /**
     * @return array<string,array{0: array<string,mixed>}>
     */
    public static function incompleteTrustChainResolutionFormProvider(): array
    {
        return [
            'no leaf entity ID' => [['leafEntityId' => '', 'trustAnchorIds' => self::TRUST_ANCHOR_ID]],
            'no Trust Anchor IDs' => [['leafEntityId' => self::LEAF_ENTITY_ID, 'trustAnchorIds' => '']],
        ];
    }


    /**
     * A chain which can not be resolved is what this page exists to diagnose, so the failure is reported
     * in the log the page renders rather than thrown.
     *
     * The successful half - the resolved metadata of each entity type - can not be reached from here,
     * because it needs a real chain from a real Trust Anchor.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testTrustChainResolutionReportsAChainItCouldNotResolve(): void
    {
        $this->sut()->trustChainResolution($this->request([
            'leafEntityId' => self::LEAF_ENTITY_ID,
            'trustAnchorIds' => self::TRUST_ANCHOR_ID,
        ]));

        $this->assertTrue($this->templateData['isFormSubmitted'] ?? null);
        $this->assertSame(self::LEAF_ENTITY_ID, $this->templateData['leafEntityId'] ?? null);
        $this->assertNotEmpty($this->templateData['logMessages'] ?? []);
        $this->assertArrayHasKey('trustChainBag', $this->templateData);
        $this->assertNull($this->templateData['trustChainBag']);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function testTrustMarkValidationRendersTheFormBeforeItIsSubmitted(): void
    {
        $this->sut()->trustMarkValidation($this->request());

        $this->assertFalse($this->templateData['isFormSubmitted'] ?? null);
        $this->assertNull($this->templateData['trustMarkType']);
        $this->assertNull($this->templateData['leafEntityId']);
        $this->assertNull($this->templateData['trustAnchorId']);
    }


    /**
     * @param array<string,mixed> $body
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    #[DataProvider('incompleteTrustMarkValidationFormProvider')]
    public function testTrustMarkValidationRefusesAnIncompleteForm(array $body): void
    {
        $this->expectException(OidcException::class);

        $this->sut()->trustMarkValidation($this->request($body));
    }


    /**
     * @return array<string,array{0: array<string,mixed>}>
     */
    public static function incompleteTrustMarkValidationFormProvider(): array
    {
        return [
            'no Trust Mark type' => [[
                'trustMarkType' => '',
                'leafEntityId' => self::LEAF_ENTITY_ID,
                'trustAnchorId' => self::TRUST_ANCHOR_ID,
            ]],
            'no leaf entity ID' => [[
                'trustMarkType' => self::TRUST_MARK_TYPE,
                'leafEntityId' => '',
                'trustAnchorId' => self::TRUST_ANCHOR_ID,
            ]],
            'no Trust Anchor ID' => [[
                'trustMarkType' => self::TRUST_MARK_TYPE,
                'leafEntityId' => self::LEAF_ENTITY_ID,
                'trustAnchorId' => '',
            ]],
        ];
    }


    /**
     * A Trust Mark says something about a leaf under a Trust Anchor, so there is nothing to validate
     * until a chain between the two has been established. The failure to establish one names both, since
     * that is what an administrator has to go and look at.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function testTrustMarkValidationReportsThatNoChainCouldBeResolved(): void
    {
        $this->trustChainError = new TrustChainException('No chain.');

        $this->sut()->trustMarkValidation($this->request([
            'trustMarkType' => self::TRUST_MARK_TYPE,
            'leafEntityId' => self::LEAF_ENTITY_ID,
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
        ]));

        $logMessages = implode("\n", (array)($this->templateData['logMessages'] ?? []));

        $this->assertStringContainsString(self::LEAF_ENTITY_ID, $logMessages);
        $this->assertStringContainsString(self::TRUST_ANCHOR_ID, $logMessages);
        $this->assertTrue($this->templateData['isFormSubmitted'] ?? null);
    }


    /**
     * Validation is attempted against the chain that was resolved, and what it says about the Trust Mark
     * is reported on the page rather than thrown - a Trust Mark which does not validate is an answer,
     * not an error.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     */
    public function testTrustMarkValidationReportsWhatValidationSaid(): void
    {
        $this->trustChainResolverMock->expects($this->once())
            ->method('for')
            ->with(self::LEAF_ENTITY_ID, [self::TRUST_ANCHOR_ID]);

        $this->sut()->trustMarkValidation($this->request([
            'trustMarkType' => self::TRUST_MARK_TYPE,
            'leafEntityId' => self::LEAF_ENTITY_ID,
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
        ]));

        $this->assertSame(self::TRUST_MARK_TYPE, $this->templateData['trustMarkType'] ?? null);
        $this->assertNotEmpty($this->templateData['logMessages'] ?? []);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryRendersTheFormBeforeItIsSubmitted(): void
    {
        $this->sut()->federationDiscovery($this->request());

        $this->assertFalse($this->templateData['isFormSubmitted'] ?? null);
        $this->assertSame([], $this->templateData['entities'] ?? null);
        $this->assertSame(0, $this->templateData['totalCount'] ?? null);
        $this->assertSame(50, $this->templateData['pageLimit'] ?? null);
        $this->assertSame('entity_id', $this->templateData['sortBy'] ?? null);
        $this->assertSame('asc', $this->templateData['sortOrder'] ?? null);
        $this->assertSame([self::TRUST_ANCHOR_ID], $this->templateData['trustAnchorIds'] ?? null);
        // The filter offers every entity type the specification defines, not a list kept in step by hand.
        $this->assertSame(
            array_map(static fn(EntityTypesEnum $case): string => $case->value, EntityTypesEnum::cases()),
            $this->templateData['entityTypeOptions'] ?? null,
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryReportsAConfigurationItCanNotRead(): void
    {
        $this->trustAnchorIdsError = new RuntimeException('Trust Anchors are malformed.');

        $this->sut()->federationDiscovery($this->request());

        $this->assertSame([], $this->templateData['trustAnchorIds'] ?? null);
        $this->assertStringContainsString(
            'Trust Anchors are malformed.',
            implode("\n", (array)($this->templateData['logMessages'] ?? [])),
        );
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryRefusesAFormWithNoTrustAnchor(): void
    {
        $this->expectException(OidcException::class);

        $this->sut()->federationDiscovery($this->request(['trustAnchorId' => '']));
    }


    /**
     * A federation whose Trust Anchor can not be reached yields no entities, and the page says so rather
     * than rendering an empty table with no explanation.
     *
     * What can not be reached from here is the loop which turns discovered entities into rows: that needs
     * a real federation to have been walked.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryReportsAFederationItCouldNotReach(): void
    {
        $this->sut()->federationDiscovery($this->request([
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
            'filterQuery' => 'university',
            'sortBy' => 'display_name',
            'sortOrder' => 'desc',
            'pageLimit' => '25',
        ]));

        $this->assertTrue($this->templateData['isFormSubmitted'] ?? null);
        $this->assertSame([], $this->templateData['entities'] ?? null);
        $this->assertStringContainsString(
            self::TRUST_ANCHOR_ID,
            implode("\n", (array)($this->templateData['logMessages'] ?? [])),
        );
        // What was asked for is handed back to the form, so a failed attempt can be corrected rather than
        // retyped.
        $this->assertSame('university', $this->templateData['filterQuery'] ?? null);
        $this->assertSame('display_name', $this->templateData['sortBy'] ?? null);
        $this->assertSame('desc', $this->templateData['sortOrder'] ?? null);
        $this->assertSame(25, $this->templateData['pageLimit'] ?? null);
    }


    /**
     * Discovery walks a federation, so it fails in as many ways as the network and the entities in it do.
     * Whatever went wrong belongs on the page - naming the Trust Anchor it was walking - rather than in an
     * error handler, because this page is where an administrator came to find out.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryReportsAnErrorFromTheWalkItself(): void
    {
        // A page token which is not one this page issued, which is as far as the walk gets.
        $this->sut()->federationDiscovery($this->request([
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
            'pageFrom' => 'not a page token',
        ]));

        $this->assertStringContainsString(
            'Error during entity discovery under Trust Anchor',
            implode("\n", (array)($this->templateData['logMessages'] ?? [])),
        );
        $this->assertSame([], $this->templateData['entities'] ?? null);
    }


    /**
     * An entity's name comes from whichever of its metadata types carries one, so sorting by it has to
     * look in each of them rather than in one and call the rest unnamed.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryCanSortByOrganizationName(): void
    {
        $this->sut()->federationDiscovery($this->request([
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
            'sortBy' => 'organization_name',
        ]));

        $this->assertSame('organization_name', $this->templateData['sortBy'] ?? null);
    }


    /**
     * Anything else would be a sort order the collection can not be asked for.
     *
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testFederationDiscoveryFallsBackToAscendingForAnUnknownSortOrder(): void
    {
        $this->sut()->federationDiscovery($this->request([
            'trustAnchorId' => self::TRUST_ANCHOR_ID,
            'sortOrder' => 'sideways',
        ]));

        $this->assertSame('asc', $this->templateData['sortOrder'] ?? null);
    }


    /**
     * @throws \SimpleSAML\Error\ConfigurationError
     * @throws \SimpleSAML\Module\oidc\Exceptions\OidcException
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testRendersEachPageUnderItsOwnMenuEntry(): void
    {
        $built = [];

        $this->templateFactoryMock = $this->createMock(TemplateFactory::class);
        $this->templateFactoryMock->method('build')->willReturnCallback(
            function (string $templateName, array $data, ?string $activeHrefPath = null) use (&$built): Template {
                $built[] = [$templateName, $activeHrefPath];

                return $this->createMock(Template::class);
            },
        );

        $sut = $this->sut();
        $sut->trustChainResolution($this->request());
        $sut->trustMarkValidation($this->request());
        $sut->federationDiscovery($this->request());

        $this->assertSame(
            [
                ['oidc:tests/trust-chain-resolution.twig', RoutesEnum::AdminTestTrustChainResolution->value],
                ['oidc:tests/trust-mark-validation.twig', RoutesEnum::AdminTestTrustMarkValidation->value],
                ['oidc:tests/federation-discovery.twig', RoutesEnum::AdminTestFederationDiscovery->value],
            ],
            $built,
        );
    }
}
