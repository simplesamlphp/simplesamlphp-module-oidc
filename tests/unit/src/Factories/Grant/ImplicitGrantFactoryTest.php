<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories\Grant;

use DateInterval;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Factories\Grant\ImplicitGrantFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Services\IdTokenBuilder;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

/**
 * The factory behind the implicit grant.
 *
 * `routing/services/services.yml` names `build` as the factory of the ImplicitGrant service, which the
 * AuthorizationServerFactory takes in its constructor; nothing else calls it. The factory's whole job is to
 * hand the grant its nine collaborators and the configured access token lifetime. That lifetime is the
 * grant's own: the implicit grant issues its tokens at the authorization endpoint, where no server hands it
 * one, so what the factory gives its constructor is what its tokens get.
 *
 * The grant keeps all of it to itself, in properties without getters, so the tests read the built grant back
 * by reflection, property by property, each collaborator pinned by identity.
 */
#[CoversClass(ImplicitGrantFactory::class)]
#[UsesClass(ImplicitGrant::class)]
#[AllowMockObjectsWithoutExpectations]
class ImplicitGrantFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $idTokenBuilderMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $accessTokenEntityFactoryMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $subjectResolverMock;

    protected MockObject $accessTokenClaimsResolverMock;

    protected DateInterval $accessTokenDuration;


    protected function setUp(): void
    {
        $this->accessTokenDuration = new DateInterval('PT23M');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getAccessTokenDuration')->willReturn($this->accessTokenDuration);

        $this->idTokenBuilderMock = $this->createMock(IdTokenBuilder::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->subjectResolverMock = $this->createMock(SubjectResolver::class);
        $this->accessTokenClaimsResolverMock = $this->createMock(AccessTokenClaimsResolver::class);
    }


    protected function sut(): ImplicitGrantFactory
    {
        return new ImplicitGrantFactory(
            $this->moduleConfigMock,
            $this->idTokenBuilderMock,
            $this->requestRulesManagerMock,
            $this->accessTokenRepositoryMock,
            $this->requestParamsResolverMock,
            $this->accessTokenEntityFactoryMock,
            $this->loggerServiceMock,
            $this->userRepositoryMock,
            $this->subjectResolverMock,
            $this->accessTokenClaimsResolverMock,
        );
    }


    protected function propertyOf(ImplicitGrant $grant, string $property): mixed
    {
        return (new ReflectionProperty($grant, $property))->getValue($grant);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(ImplicitGrantFactory::class, $this->sut());
    }


    /**
     * The built grant is the implicit grant, and every collaborator the factory was given is in its place on
     * it.
     */
    public function testBuildsTheImplicitGrantAroundTheFactorysCollaborators(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame(ImplicitGrant::class, $grant::class);
        $this->assertSame(GrantTypesEnum::Implicit->value, $grant->getIdentifier());
        $this->assertSame($this->idTokenBuilderMock, $this->propertyOf($grant, 'idTokenBuilder'));
        $this->assertSame($this->accessTokenRepositoryMock, $this->propertyOf($grant, 'accessTokenRepository'));
        $this->assertSame($this->requestRulesManagerMock, $this->propertyOf($grant, 'requestRulesManager'));
        $this->assertSame($this->requestParamsResolverMock, $this->propertyOf($grant, 'requestParamsResolver'));
        $this->assertSame($this->accessTokenEntityFactoryMock, $this->propertyOf($grant, 'accessTokenEntityFactory'));
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($grant, 'loggerService'));
        $this->assertSame($this->userRepositoryMock, $this->propertyOf($grant, 'userRepository'));
        $this->assertSame($this->subjectResolverMock, $this->propertyOf($grant, 'subjectResolver'));
        $this->assertSame($this->accessTokenClaimsResolverMock, $this->propertyOf($grant, 'accessTokenClaimsResolver'));
    }


    /**
     * The access token lifetime is the configured one, the very object, which is what the grant stamps on the
     * tokens it issues at the authorization endpoint.
     */
    public function testGivesTheGrantTheConfiguredAccessTokenLifetime(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame($this->accessTokenDuration, $this->propertyOf($grant, 'accessTokenTTL'));
    }
}
