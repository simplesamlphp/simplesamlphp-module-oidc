<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionNamedType;
use SimpleSAML\Module\oidc\Bridges\SspBridge;
use SimpleSAML\Module\oidc\Factories\AuthSimpleFactory;
use SimpleSAML\Module\oidc\Factories\Entities\ClientEntityFactory;
use SimpleSAML\Module\oidc\Factories\RequestRulesManagerFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\CodeChallengeVerifiersRepository;
use SimpleSAML\Module\oidc\Repositories\PushedAuthorizationRequestRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\AbstractRule;
use SimpleSAML\Module\oidc\Server\RequestRules\Rules\ClientRule;
use SimpleSAML\Module\oidc\Server\ResponseModes\FormPostResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\FragmentResponseMode;
use SimpleSAML\Module\oidc\Server\ResponseModes\QueryResponseMode;
use SimpleSAML\Module\oidc\Services\AuthenticationService;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\ClaimTranslatorExtractor;
use SimpleSAML\Module\oidc\Utils\FederationCache;
use SimpleSAML\Module\oidc\Utils\FederationParticipationValidator;
use SimpleSAML\Module\oidc\Utils\JwksResolver;
use SimpleSAML\Module\oidc\Utils\ProtocolCache;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\OpenID\Core;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwks;

/**
 * The factory which assembles the request rules the whole protocol layer runs on.
 *
 * Nothing in `src/` mentions this class. Symfony reaches it through `routing/services/services.yml`, which
 * names `build` as the factory for the single RequestRulesManager shared by the authorization server, the
 * authorization code, pre-authorized code and implicit grants, and the pushed authorization request
 * endpoint. It is always called there with no arguments, so the default rule set is the only one production
 * ever sees; the `$rules` parameter is a seam for callers which do not exist yet.
 *
 * Two things can go wrong here and nowhere else, and the tests below are shaped around them.
 *
 * A rule which is written but never registered breaks nothing at construction time. The omission surfaces
 * later, when a consumer asks the manager for that rule key and gets a LogicException in the middle of a
 * live authorization request. So the registered set is checked against the rule classes which exist on
 * disk rather than against a list kept in this file, that being the only version of the check a newly
 * added rule cannot slip past.
 *
 * A rule handed the wrong collaborator is, in almost every case, impossible: no rule constructor declares
 * the same type twice, so PHP rejects a swap before a test could see it. The exception is ClientRule's
 * federation cache, which is optional and defaults to null -- dropping that argument compiles, satisfies
 * static analysis, and quietly turns entity statement caching off. The wiring test therefore reads each
 * rule's own constructor signature and asserts the instance behind every parameter, so an argument which
 * stops being passed is caught by the same loop as one which is passed something wrong.
 */
#[CoversClass(RequestRulesManagerFactory::class)]
#[UsesClass(RequestRulesManager::class)]
#[AllowMockObjectsWithoutExpectations]
class RequestRulesManagerFactoryTest extends TestCase
{
    /** Rules the factory registers when it is left to pick them itself. */
    private const int DEFAULT_RULE_COUNT = 27;

    /**
     * Constructor parameters across all of those rules, counted so that the wiring test cannot pass by
     * asserting nothing. Adding a dependency to any rule is expected to move this number.
     */
    private const int DEFAULT_RULE_COLLABORATOR_COUNT = 86;


    private ModuleConfig&MockObject $moduleConfigMock;

    private LoggerService&MockObject $loggerMock;

    private ClientRepository&MockObject $clientRepositoryMock;

    private AuthSimpleFactory&MockObject $authSimpleFactoryMock;

    private AuthenticationService&MockObject $authenticationServiceMock;

    private ScopeRepository&MockObject $scopeRepositoryMock;

    private CodeChallengeVerifiersRepository&MockObject $codeChallengeVerifiersRepositoryMock;

    private ClaimTranslatorExtractor&MockObject $claimTranslatorExtractorMock;

    private RequestParamsResolver&MockObject $requestParamsResolverMock;

    private ClientEntityFactory&MockObject $clientEntityFactoryMock;

    private Federation&MockObject $federationMock;

    private Helpers&MockObject $helpersMock;

    private JwksResolver&MockObject $jwksResolverMock;

    private FederationParticipationValidator&MockObject $federationParticipationValidatorMock;

    private SspBridge&MockObject $sspBridgeMock;

    private Jwks&MockObject $jwksMock;

    private Core&MockObject $coreMock;

    private AuthenticatedOAuth2ClientResolver&MockObject $authenticatedOAuth2ClientResolverMock;

    private PushedAuthorizationRequestRepository&MockObject $pushedAuthorizationRequestRepositoryMock;

    private QueryResponseMode&MockObject $queryResponseModeMock;

    private FragmentResponseMode&MockObject $fragmentResponseModeMock;

    private FormPostResponseMode&MockObject $formPostResponseModeMock;

    private FederationCache&MockObject $federationCacheMock;

    private ProtocolCache&MockObject $protocolCacheMock;


    protected function setUp(): void
    {
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->loggerMock = $this->createMock(LoggerService::class);
        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->authSimpleFactoryMock = $this->createMock(AuthSimpleFactory::class);
        $this->authenticationServiceMock = $this->createMock(AuthenticationService::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepository::class);
        $this->codeChallengeVerifiersRepositoryMock = $this->createMock(CodeChallengeVerifiersRepository::class);
        $this->claimTranslatorExtractorMock = $this->createMock(ClaimTranslatorExtractor::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->clientEntityFactoryMock = $this->createMock(ClientEntityFactory::class);
        $this->federationMock = $this->createMock(Federation::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->jwksResolverMock = $this->createMock(JwksResolver::class);
        $this->federationParticipationValidatorMock = $this->createMock(FederationParticipationValidator::class);
        $this->sspBridgeMock = $this->createMock(SspBridge::class);
        $this->jwksMock = $this->createMock(Jwks::class);
        $this->coreMock = $this->createMock(Core::class);
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->pushedAuthorizationRequestRepositoryMock = $this->createMock(
            PushedAuthorizationRequestRepository::class,
        );
        $this->queryResponseModeMock = $this->createMock(QueryResponseMode::class);
        $this->fragmentResponseModeMock = $this->createMock(FragmentResponseMode::class);
        $this->formPostResponseModeMock = $this->createMock(FormPostResponseMode::class);
        $this->federationCacheMock = $this->createMock(FederationCache::class);
        $this->protocolCacheMock = $this->createMock(ProtocolCache::class);
    }


    /**
     * @param bool $withFederationCache Whether the factory is given a federation cache at all. The container
     *   builds that one from CacheFactory::forFederation(), which returns null when no cache is configured,
     *   so a factory without it is the ordinary case rather than a contrived one.
     */
    private function sut(bool $withFederationCache = true): RequestRulesManagerFactory
    {
        return new RequestRulesManagerFactory(
            $this->moduleConfigMock,
            $this->loggerMock,
            $this->clientRepositoryMock,
            $this->authSimpleFactoryMock,
            $this->authenticationServiceMock,
            $this->scopeRepositoryMock,
            $this->codeChallengeVerifiersRepositoryMock,
            $this->claimTranslatorExtractorMock,
            $this->requestParamsResolverMock,
            $this->clientEntityFactoryMock,
            $this->federationMock,
            $this->helpersMock,
            $this->jwksResolverMock,
            $this->federationParticipationValidatorMock,
            $this->sspBridgeMock,
            $this->jwksMock,
            $this->coreMock,
            $this->authenticatedOAuth2ClientResolverMock,
            $this->pushedAuthorizationRequestRepositoryMock,
            $this->queryResponseModeMock,
            $this->fragmentResponseModeMock,
            $this->formPostResponseModeMock,
            $withFederationCache ? $this->federationCacheMock : null,
            $this->protocolCacheMock,
        );
    }


    /**
     * The collaborators the factory holds, keyed by the type a rule constructor declares for them.
     *
     * Two of the factory's own dependencies are deliberately missing. ScopeRepository is here under
     * ScopeRepositoryInterface, which is the type ScopeRule declares. ProtocolCache is not here at all,
     * because no rule is given it: the factory takes it in its constructor and never reads it.
     *
     * @return array<class-string,object>
     */
    private function expectedCollaborators(): array
    {
        return [
            AuthenticatedOAuth2ClientResolver::class => $this->authenticatedOAuth2ClientResolverMock,
            AuthenticationService::class => $this->authenticationServiceMock,
            AuthSimpleFactory::class => $this->authSimpleFactoryMock,
            ClaimTranslatorExtractor::class => $this->claimTranslatorExtractorMock,
            ClientEntityFactory::class => $this->clientEntityFactoryMock,
            ClientRepository::class => $this->clientRepositoryMock,
            CodeChallengeVerifiersRepository::class => $this->codeChallengeVerifiersRepositoryMock,
            Core::class => $this->coreMock,
            Federation::class => $this->federationMock,
            FederationCache::class => $this->federationCacheMock,
            FederationParticipationValidator::class => $this->federationParticipationValidatorMock,
            FormPostResponseMode::class => $this->formPostResponseModeMock,
            FragmentResponseMode::class => $this->fragmentResponseModeMock,
            Helpers::class => $this->helpersMock,
            Jwks::class => $this->jwksMock,
            JwksResolver::class => $this->jwksResolverMock,
            LoggerService::class => $this->loggerMock,
            ModuleConfig::class => $this->moduleConfigMock,
            PushedAuthorizationRequestRepository::class => $this->pushedAuthorizationRequestRepositoryMock,
            QueryResponseMode::class => $this->queryResponseModeMock,
            RequestParamsResolver::class => $this->requestParamsResolverMock,
            ScopeRepositoryInterface::class => $this->scopeRepositoryMock,
            SspBridge::class => $this->sspBridgeMock,
        ];
    }


    /**
     * Read a property a class keeps to itself. The factory publishes nothing about what it built, and an
     * accessor added to production code for a test's benefit would be the worse trade of the two.
     */
    private function propertyValue(object $object, string $name): mixed
    {
        $class = new ReflectionClass($object);

        $this->assertTrue(
            $class->hasProperty($name),
            sprintf('%s has no property $%s to read.', $class->getName(), $name),
        );

        return $class->getProperty($name)->getValue($object);
    }


    /**
     * @return array<string,\SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface>
     */
    private function registeredRules(RequestRulesManager $manager): array
    {
        $rules = $this->propertyValue($manager, 'rules');
        $this->assertIsArray($rules);

        /** @var array<string,\SimpleSAML\Module\oidc\Server\RequestRules\Interfaces\RequestRuleInterface> $rules */
        return $rules;
    }


    /**
     * The default set has to be the complete set.
     *
     * A rule left out of the factory is invisible until a consumer names its key, at which point the manager
     * throws LogicException while an authorization request is in flight. Checking the registered set against
     * the classes on disk is what makes a newly written rule fail here instead of there. It fails in the
     * other direction too: a rule which is registered but no longer exists under that namespace.
     *
     * Comparing keys against file names is only meaningful because the manager files each rule under
     * whatever getKey() returns, and AbstractRule defines that as the rule's own class name -- which is what
     * consumers pass to check(). A rule which overrode getKey() would sit under a key nobody asks for, as
     * absent as one never registered and with no error or log line to say so, and shows up here as a class
     * on disk which nothing registered.
     */
    public function testEveryRuleThatExistsIsRegisteredAmongTheDefaults(): void
    {
        $abstractRule = new ReflectionClass(AbstractRule::class);
        $files = glob(dirname((string)$abstractRule->getFileName()) . DIRECTORY_SEPARATOR . '*.php');
        $this->assertIsArray($files);
        $this->assertNotEmpty($files, 'Found no rule files at all, so this test proves nothing.');

        $onDisk = [];

        foreach ($files as $file) {
            /** @var class-string $candidate */
            $candidate = $abstractRule->getNamespaceName() . '\\' . basename($file, '.php');
            $this->assertTrue(class_exists($candidate), sprintf('%s does not declare %s.', $file, $candidate));

            $reflection = new ReflectionClass($candidate);

            if ($reflection->isAbstract() || ! $reflection->implementsInterface(RequestRuleInterface::class)) {
                continue;
            }

            $onDisk[] = $candidate;
        }

        $rules = $this->registeredRules($this->sut()->build());
        $this->assertCount(
            self::DEFAULT_RULE_COUNT,
            $rules,
            'The default rule set changed size. Both counts kept at the top of this file have to follow.',
        );

        sort($onDisk);
        $registered = array_keys($rules);
        sort($registered);

        $this->assertSame(
            $onDisk,
            $registered,
            'The rules which exist and the rules the factory registers have drifted apart.',
        );
    }


    /**
     * Every rule is built out of the factory's own collaborators, and out of nothing else.
     *
     * The parameters to check come from each rule's constructor rather than from a list kept here, so a rule
     * which gains a dependency is checked for it without this test being edited, and a rule which asks for
     * something the factory does not hold fails loudly instead of going quietly unchecked. The count at the
     * end is what keeps the loop honest: without it a bug which registered no rules at all would pass.
     */
    public function testEveryDefaultRuleIsBuiltFromTheFactorysOwnCollaborators(): void
    {
        $expected = $this->expectedCollaborators();
        $checked = 0;

        foreach ($this->registeredRules($this->sut()->build()) as $ruleClass => $rule) {
            $constructor = (new ReflectionClass($rule))->getConstructor();
            $this->assertNotNull($constructor, sprintf('%s has no constructor.', $ruleClass));

            foreach ($constructor->getParameters() as $parameter) {
                $type = $parameter->getType();
                $this->assertInstanceOf(
                    ReflectionNamedType::class,
                    $type,
                    sprintf('%s::$%s is not of a single named type.', $ruleClass, $parameter->getName()),
                );

                $this->assertArrayHasKey($type->getName(), $expected, sprintf(
                    '%s asks for a %s, which the factory is not known to hold. Add it to expectedCollaborators().',
                    $ruleClass,
                    $type->getName(),
                ));

                $this->assertSame(
                    $expected[$type->getName()],
                    $this->propertyValue($rule, $parameter->getName()),
                    sprintf('%s was not given the factory\'s %s.', $ruleClass, $type->getName()),
                );

                $checked++;
            }
        }

        $this->assertSame(
            self::DEFAULT_RULE_COLLABORATOR_COUNT,
            $checked,
            'Checked a different number of collaborators than the rules are known to take.',
        );
    }


    /**
     * ClientRule's federation cache is the one argument in the whole table which can be dropped without
     * anything noticing: it is optional and defaults to null, so an omission compiles, passes static
     * analysis, and turns entity statement caching off for federated clients. Only the first half below
     * catches that. An argument which stopped being passed and one which was never passed leave the same
     * null behind, so the second half cannot tell them apart and does not try to.
     *
     * What the second half is for is that the null is the ordinary case rather than a contrived one: the
     * container builds that cache from CacheFactory::forFederation(), which returns null whenever no cache
     * is configured. The whole rule set therefore has to keep building when there is nothing to cache with,
     * which is what would stop being true if that parameter were ever made non-nullable.
     */
    public function testTheClientRuleIsGivenTheFederationCacheOrTheNullThereIsInstead(): void
    {
        $withCache = $this->registeredRules($this->sut()->build())[ClientRule::class];
        $this->assertSame($this->federationCacheMock, $this->propertyValue($withCache, 'federationCache'));

        $withoutCache = $this->registeredRules($this->sut(withFederationCache: false)->build());
        $this->assertCount(self::DEFAULT_RULE_COUNT, $withoutCache);
        $this->assertNull($this->propertyValue($withoutCache[ClientRule::class], 'federationCache'));
    }


    /**
     * Rules passed in replace the defaults rather than joining them.
     */
    public function testExplicitlyPassedRulesReplaceTheDefaults(): void
    {
        $rule = $this->createMock(RequestRuleInterface::class);
        $rule->method('getKey')->willReturn('some-rule-key');

        $this->assertSame(['some-rule-key' => $rule], $this->registeredRules($this->sut()->build([$rule])));
    }


    /**
     * An empty array is a choice, not an absent argument.
     *
     * The defaults are substituted with `??=`, which only replaces null, so a caller asking for no rules
     * gets no rules. Written as `?:` it would read an empty array as a request for the defaults instead,
     * and no test which passes a non-empty array could tell those two apart.
     */
    public function testAnEmptyRuleArrayIsTakenAtFaceValue(): void
    {
        $this->assertSame([], $this->registeredRules($this->sut()->build([])));
    }


    /**
     * RequestRulesManager's own constructor defaults its logger to a fresh LoggerService, so a factory which
     * forgot to pass one would build a working manager which logs somewhere other than the rest of the
     * module. Only the identity of the instance says which of the two happened.
     */
    public function testTheManagerIsGivenTheLoggerTheFactoryHolds(): void
    {
        $this->assertSame($this->loggerMock, $this->propertyValue($this->sut()->build(), 'loggerService'));
    }
}
