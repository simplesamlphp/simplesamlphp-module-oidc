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
use SimpleSAML\Module\oidc\Factories\Entities\AuthCodeEntityFactory;
use SimpleSAML\Module\oidc\Factories\Grant\PreAuthCodeGrantFactory;
use SimpleSAML\Module\oidc\Helpers;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\AuthCodeRepository;
use SimpleSAML\Module\oidc\Repositories\RefreshTokenRepository;
use SimpleSAML\Module\oidc\Repositories\UserRepository;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\AccessTokenClaimsResolver;
use SimpleSAML\Module\oidc\Utils\RequestParamsResolver;
use SimpleSAML\Module\oidc\Utils\SubjectResolver;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

/**
 * The factory behind the pre-authorized code grant.
 *
 * `routing/services/services.yml` names `build` as the factory of the PreAuthCodeGrant service, which the
 * AuthorizationServerFactory takes in its constructor and enables when Verifiable Credential Issuance is;
 * nothing else calls it. The factory's whole job is to hand the grant its thirteen collaborators and the two
 * configured lifetimes: the authorization code lifetime through the constructor, the refresh token lifetime
 * through League's setter, over the month League's constructor starts every authorization code grant with.
 *
 * The grant keeps all of it to itself, in properties without getters, so the tests read the built grant back
 * by reflection, property by property. Each collaborator is pinned by identity; a swap between two of them
 * would be a type error, but the two lifetimes are both a DateInterval and are pinned to distinct
 * configured values for that reason.
 */
#[CoversClass(PreAuthCodeGrantFactory::class)]
#[UsesClass(PreAuthCodeGrant::class)]
#[AllowMockObjectsWithoutExpectations]
class PreAuthCodeGrantFactoryTest extends TestCase
{
    protected MockObject $moduleConfigMock;

    protected MockObject $authCodeRepositoryMock;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $refreshTokenRepositoryMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $requestParamsResolverMock;

    protected MockObject $accessTokenEntityFactoryMock;

    protected MockObject $authCodeEntityFactoryMock;

    protected MockObject $refreshTokenIssuerMock;

    protected MockObject $helpersMock;

    protected MockObject $loggerServiceMock;

    protected MockObject $userRepositoryMock;

    protected MockObject $subjectResolverMock;

    protected MockObject $accessTokenClaimsResolverMock;

    protected DateInterval $authCodeDuration;

    protected DateInterval $refreshTokenDuration;


    protected function setUp(): void
    {
        $this->authCodeDuration = new DateInterval('PT10M');
        $this->refreshTokenDuration = new DateInterval('P2W');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getAuthCodeDuration')->willReturn($this->authCodeDuration);
        $this->moduleConfigMock->method('getRefreshTokenDuration')->willReturn($this->refreshTokenDuration);

        $this->authCodeRepositoryMock = $this->createMock(AuthCodeRepository::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepository::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->requestParamsResolverMock = $this->createMock(RequestParamsResolver::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->authCodeEntityFactoryMock = $this->createMock(AuthCodeEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->helpersMock = $this->createMock(Helpers::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
        $this->userRepositoryMock = $this->createMock(UserRepository::class);
        $this->subjectResolverMock = $this->createMock(SubjectResolver::class);
        $this->accessTokenClaimsResolverMock = $this->createMock(AccessTokenClaimsResolver::class);
    }


    protected function sut(): PreAuthCodeGrantFactory
    {
        return new PreAuthCodeGrantFactory(
            $this->moduleConfigMock,
            $this->authCodeRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->refreshTokenRepositoryMock,
            $this->requestRulesManagerMock,
            $this->requestParamsResolverMock,
            $this->accessTokenEntityFactoryMock,
            $this->authCodeEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->helpersMock,
            $this->loggerServiceMock,
            $this->userRepositoryMock,
            $this->subjectResolverMock,
            $this->accessTokenClaimsResolverMock,
        );
    }


    protected function propertyOf(PreAuthCodeGrant $grant, string $property): mixed
    {
        return (new ReflectionProperty($grant, $property))->getValue($grant);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(PreAuthCodeGrantFactory::class, $this->sut());
    }


    /**
     * The built grant is the pre-authorized code grant, answering to its own identifier rather than the
     * parent's, and every collaborator the factory was given is in its place on it.
     */
    public function testBuildsThePreAuthorizedCodeGrantAroundTheFactorysCollaborators(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame(PreAuthCodeGrant::class, $grant::class);
        $this->assertSame(GrantTypesEnum::PreAuthorizedCode->value, $grant->getIdentifier());
        $this->assertSame($this->authCodeRepositoryMock, $this->propertyOf($grant, 'authCodeRepository'));
        $this->assertSame($this->accessTokenRepositoryMock, $this->propertyOf($grant, 'accessTokenRepository'));
        $this->assertSame($this->refreshTokenRepositoryMock, $this->propertyOf($grant, 'refreshTokenRepository'));
        $this->assertSame($this->requestRulesManagerMock, $this->propertyOf($grant, 'requestRulesManager'));
        $this->assertSame($this->requestParamsResolverMock, $this->propertyOf($grant, 'requestParamsResolver'));
        $this->assertSame($this->accessTokenEntityFactoryMock, $this->propertyOf($grant, 'accessTokenEntityFactory'));
        $this->assertSame($this->authCodeEntityFactoryMock, $this->propertyOf($grant, 'authCodeEntityFactory'));
        $this->assertSame($this->refreshTokenIssuerMock, $this->propertyOf($grant, 'refreshTokenIssuer'));
        $this->assertSame($this->helpersMock, $this->propertyOf($grant, 'helpers'));
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($grant, 'loggerService'));
        $this->assertSame($this->userRepositoryMock, $this->propertyOf($grant, 'userRepository'));
        $this->assertSame($this->subjectResolverMock, $this->propertyOf($grant, 'subjectResolver'));
        $this->assertSame($this->accessTokenClaimsResolverMock, $this->propertyOf($grant, 'accessTokenClaimsResolver'));
    }


    /**
     * The refresh token lifetime is what the grant hands the refresh token issuer. The authorization code
     * lifetime goes in through the constructor as the parent's does, though this grant only redeems the codes
     * the CredentialOfferUriFactory creates and never reads it; it is pinned as handed over all the same, so
     * a swap with the refresh token lifetime cannot pass unseen.
     */
    public function testGivesTheGrantTheConfiguredAuthorizationCodeAndRefreshTokenLifetimes(): void
    {
        $grant = $this->sut()->build();

        $this->assertSame($this->authCodeDuration, $this->propertyOf($grant, 'authCodeTTL'));
        $this->assertSame($this->refreshTokenDuration, $this->propertyOf($grant, 'refreshTokenTTL'));
    }
}
