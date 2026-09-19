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
use SimpleSAML\Module\oidc\Factories\Grant\RefreshTokenGrantFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

/**
 * The factory behind the refresh token grant.
 *
 * `routing/services/services.yml` names `build` as the factory of the RefreshTokenGrant service, which the
 * AuthorizationServerFactory takes in its constructor; nothing else calls it. The factory's whole job is to
 * hand the grant its eight collaborators and, through League's setter, the configured refresh token lifetime,
 * over the month League's constructor starts every refresh token grant with. That lifetime is what the grant
 * hands the refresh token issuer for the refresh token it issues with the new access token, and what it
 * reads the old token's issue time back from.
 *
 * The grant keeps all of it to itself, in properties without getters, so the tests read the built grant back
 * by reflection, property by property, each collaborator pinned by identity.
 */
#[CoversClass(RefreshTokenGrantFactory::class)]
#[UsesClass(RefreshTokenGrant::class)]
#[AllowMockObjectsWithoutExpectations]
class RefreshTokenGrantFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $refreshTokenRepositoryMock;

    protected MockObject $accessTokenEntityFactoryMock;

    protected MockObject $refreshTokenIssuerMock;

    protected MockObject $authenticatedOAuth2ClientResolverMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $subjectResolverMock;

    protected MockObject $accessTokenClaimsResolverMock;

    protected DateInterval $refreshTokenDuration;


    protected function setUp(): void
    {
        $this->refreshTokenDuration = new DateInterval('P2W');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getRefreshTokenDuration')->willReturn($this->refreshTokenDuration);

        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepository::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->authenticatedOAuth2ClientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->subjectResolverMock = $this->createMock(SubjectResolver::class);
        $this->accessTokenClaimsResolverMock = $this->createMock(AccessTokenClaimsResolver::class);
    }


    protected function sut(): RefreshTokenGrantFactory
    {
        return new RefreshTokenGrantFactory(
            $this->moduleConfigMock,
            $this->refreshTokenRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->authenticatedOAuth2ClientResolverMock,
            $this->loggerServiceMock,
            $this->userRepositoryMock,
            $this->subjectResolverMock,
            $this->accessTokenClaimsResolverMock,
        );
    }


    protected function propertyOf(RefreshTokenGrant $grant, string $property): mixed
    {
        return (new ReflectionProperty($grant, $property))->getValue($grant);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(RefreshTokenGrantFactory::class, $this->sut());
    }


    /**
     * The built grant is the refresh token grant, and every collaborator the factory was given is in its
     * place on it.
     */
    public function testBuildsTheRefreshTokenGrantAroundTheFactorysCollaborators(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame(RefreshTokenGrant::class, $grant::class);
        $this->assertSame(GrantTypesEnum::RefreshToken->value, $grant->getIdentifier());
        $this->assertSame($this->refreshTokenRepositoryMock, $this->propertyOf($grant, 'refreshTokenRepository'));
        $this->assertSame($this->accessTokenEntityFactoryMock, $this->propertyOf($grant, 'accessTokenEntityFactory'));
        $this->assertSame($this->refreshTokenIssuerMock, $this->propertyOf($grant, 'refreshTokenIssuer'));
        $this->assertSame(
            $this->authenticatedOAuth2ClientResolverMock,
            $this->propertyOf($grant, 'authenticatedOAuth2ClientResolver'),
        );
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($grant, 'loggerService'));
        $this->assertSame($this->userRepositoryMock, $this->propertyOf($grant, 'userRepository'));
        $this->assertSame($this->subjectResolverMock, $this->propertyOf($grant, 'subjectResolver'));
        $this->assertSame($this->accessTokenClaimsResolverMock, $this->propertyOf($grant, 'accessTokenClaimsResolver'));
    }


    /**
     * The refresh token lifetime is the configured one, the very object, in place of the month League's
     * constructor set.
     */
    public function testGivesTheGrantTheConfiguredRefreshTokenLifetime(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame($this->refreshTokenDuration, $this->propertyOf($grant, 'refreshTokenTTL'));
    }
}
