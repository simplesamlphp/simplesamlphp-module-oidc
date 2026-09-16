<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Factories;

use DateInterval;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionProperty;
use SimpleSAML\Module\oidc\Factories\AuthorizationServerFactory;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Repositories\ScopeRepository;
use SimpleSAML\Module\oidc\Server\AuthorizationServer;
use SimpleSAML\Module\oidc\Server\Grants\AuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\ImplicitGrant;
use SimpleSAML\Module\oidc\Server\Grants\PreAuthCodeGrant;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\RequestRules\RequestRulesManager;
use SimpleSAML\Module\oidc\Server\ResponseTypes\TokenResponse;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Codebooks\GrantTypesEnum;

/**
 * The factory behind the one AuthorizationServer the module runs on.
 *
 * `routing/services/services.yml` names `build` as the factory of the shared AuthorizationServer service,
 * which the authorization, access token and end session controllers take in their constructors; nothing else
 * calls it. What the factory decides is which grants that server offers and what they are wired to: the
 * authorization code grant always, the implicit and refresh token grants unless the configuration leaves
 * them out, the pre-authorized code grant only when Verifiable Credential Issuance is enabled, each enabled
 * with the configured access token lifetime.
 *
 * The server keeps its grants and their lifetimes to itself, so the tests observe the wiring where it
 * surfaces. League's enableGrantType() hands each enabled grant the server's own repositories and keys
 * through the grant's setters, so a grant mock sees exactly what the factory built the server around, and a
 * grant which was not enabled sees nothing at all. The lifetime is what the server passes to the grant which
 * answers a token request, so the tests drive the token endpoint of the built server with a grant mock which
 * claims the request. The implicit grant never answers one: it issues its tokens at the authorization
 * endpoint with a lifetime of its own, from its constructor, so the lifetime the factory enables it with is
 * never read and is not pinned. The request rules manager and the logger are held by the module's subclass
 * and reach no grant, so those two are read back by reflection.
 */
#[CoversClass(AuthorizationServerFactory::class)]
#[UsesClass(AuthorizationServer::class)]
#[AllowMockObjectsWithoutExpectations]
class AuthorizationServerFactoryTest extends TestCase
{
    /** Passed on as given; the server does not read it while being built. */
    protected const string ENCRYPTION_KEY = 'encryption-key';


    protected MockObject $moduleConfigMock;

    protected MockObject $clientRepositoryMock;

    protected MockObject $accessTokenRepositoryMock;

    protected MockObject $scopeRepositoryMock;

    protected MockObject $authCodeGrantMock;

    protected MockObject $implicitGrantMock;

    protected MockObject $refreshTokenGrantMock;

    protected MockObject $tokenResponseMock;

    protected MockObject $requestRulesManagerMock;

    protected MockObject $privateKeyMock;

    protected MockObject $preAuthCodeGrantMock;

    protected MockObject $loggerServiceMock;

    protected DateInterval $accessTokenDuration;


    protected function setUp(): void
    {
        $this->accessTokenDuration = new DateInterval('PT23M');

        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);
        $this->moduleConfigMock->method('getEncryptionKey')->willReturn(self::ENCRYPTION_KEY);
        $this->moduleConfigMock->method('getAccessTokenDuration')->willReturn($this->accessTokenDuration);

        $this->clientRepositoryMock = $this->createMock(ClientRepository::class);
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->scopeRepositoryMock = $this->createMock(ScopeRepository::class);
        $this->authCodeGrantMock = $this->grantMock(AuthCodeGrant::class, GrantTypesEnum::AuthorizationCode);
        $this->implicitGrantMock = $this->grantMock(ImplicitGrant::class, GrantTypesEnum::Implicit);
        $this->refreshTokenGrantMock = $this->grantMock(RefreshTokenGrant::class, GrantTypesEnum::RefreshToken);
        $this->preAuthCodeGrantMock = $this->grantMock(PreAuthCodeGrant::class, GrantTypesEnum::PreAuthorizedCode);
        $this->tokenResponseMock = $this->createMock(TokenResponse::class);
        $this->requestRulesManagerMock = $this->createMock(RequestRulesManager::class);
        $this->privateKeyMock = $this->createMock(CryptKey::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);
    }


    /**
     * The server files each enabled grant under its identifier, so every grant mock needs the identifier of
     * the grant it stands in for, or the four would overwrite one another.
     */
    protected function grantMock(string $class, GrantTypesEnum $grantType): MockObject
    {
        $grantMock = $this->createMock($class);
        $grantMock->method('getIdentifier')->willReturn($grantType->value);

        return $grantMock;
    }


    protected function grantMockFor(GrantTypesEnum $grantType): MockObject
    {
        return match ($grantType) {
            GrantTypesEnum::AuthorizationCode => $this->authCodeGrantMock,
            GrantTypesEnum::Implicit => $this->implicitGrantMock,
            GrantTypesEnum::RefreshToken => $this->refreshTokenGrantMock,
            GrantTypesEnum::PreAuthorizedCode => $this->preAuthCodeGrantMock,
        };
    }


    /**
     * Verifiable Credential Issuance is off unless a test says so; the optional grants are on, as they are
     * out of the box, unless a test names the ones which are not.
     *
     * @param \SimpleSAML\OpenID\Codebooks\GrantTypesEnum[] $disabledGrantTypes
     */
    protected function sut(bool $vciEnabled = false, array $disabledGrantTypes = []): AuthorizationServerFactory
    {
        $this->moduleConfigMock->method('getVciEnabled')->willReturn($vciEnabled);
        $this->moduleConfigMock->method('isGrantTypeEnabled')->willReturnCallback(
            fn(GrantTypesEnum $grantType): bool => !in_array($grantType, $disabledGrantTypes, true),
        );

        return new AuthorizationServerFactory(
            $this->moduleConfigMock,
            $this->clientRepositoryMock,
            $this->accessTokenRepositoryMock,
            $this->scopeRepositoryMock,
            $this->authCodeGrantMock,
            $this->implicitGrantMock,
            $this->refreshTokenGrantMock,
            $this->tokenResponseMock,
            $this->requestRulesManagerMock,
            $this->privateKeyMock,
            $this->preAuthCodeGrantMock,
            $this->loggerServiceMock,
        );
    }


    /**
     * League's enableGrantType() hands the grant the server's repositories and keys, so these five calls are
     * the proof that the grant was enabled on a server built around the factory's own collaborators, each in
     * its place.
     */
    protected function expectGrantEnabledOnTheServer(MockObject $grantMock): void
    {
        $grantMock->expects($this->once())->method('setClientRepository')
            ->with($this->identicalTo($this->clientRepositoryMock));
        $grantMock->expects($this->once())->method('setAccessTokenRepository')
            ->with($this->identicalTo($this->accessTokenRepositoryMock));
        $grantMock->expects($this->once())->method('setScopeRepository')
            ->with($this->identicalTo($this->scopeRepositoryMock));
        $grantMock->expects($this->once())->method('setPrivateKey')
            ->with($this->identicalTo($this->privateKeyMock));
        $grantMock->expects($this->once())->method('setEncryptionKey')
            ->with($this->identicalTo(self::ENCRYPTION_KEY));
    }


    /**
     * A grant which is not enabled is not so much as asked for its identifier.
     */
    protected function expectGrantLeftOutOfTheServer(MockObject $grantMock): void
    {
        $grantMock->expects($this->never())->method($this->anything());
    }


    protected function propertyOf(AuthorizationServer $server, string $property): mixed
    {
        return (new ReflectionProperty(AuthorizationServer::class, $property))->getValue($server);
    }


    public function testCanCreateInstance(): void
    {
        $this->assertInstanceOf(AuthorizationServerFactory::class, $this->sut());
    }


    public function testBuildsTheServerAroundTheRequestRulesManagerAndTheLogger(): void
    {
        $server = $this->sut()->build();

        $this->assertSame($this->requestRulesManagerMock, $this->propertyOf($server, 'requestRulesManager'));
        $this->assertSame($this->loggerServiceMock, $this->propertyOf($server, 'loggerService'));
    }


    public function testEnablesTheOAuth2GrantsOnAServerBuiltAroundTheRepositoriesAndTheKeys(): void
    {
        $this->expectGrantEnabledOnTheServer($this->authCodeGrantMock);
        $this->expectGrantEnabledOnTheServer($this->implicitGrantMock);
        $this->expectGrantEnabledOnTheServer($this->refreshTokenGrantMock);
        $this->expectGrantLeftOutOfTheServer($this->preAuthCodeGrantMock);

        $this->sut()->build();
    }


    /**
     * A grant which the configuration leaves out is not on the server, which is what makes the setting
     * more than an advertisement: nothing can answer a request for it, so the server refuses the request
     * as one for a response type or grant type it does not support, whatever the client's registration
     * says. The authorization code grant has no such switch.
     */
    #[DataProvider('optionalGrantProvider')]
    public function testLeavesADisabledGrantOffTheServer(GrantTypesEnum $disabledGrantType): void
    {
        $this->expectGrantEnabledOnTheServer($this->authCodeGrantMock);
        $this->expectGrantLeftOutOfTheServer($this->grantMockFor($disabledGrantType));
        $this->expectGrantLeftOutOfTheServer($this->preAuthCodeGrantMock);

        $this->sut(disabledGrantTypes: [$disabledGrantType])->build();
    }


    public static function optionalGrantProvider(): array
    {
        return [
            'the implicit grant' => [GrantTypesEnum::Implicit],
            'the refresh token grant' => [GrantTypesEnum::RefreshToken],
        ];
    }


    public function testEnablesThePreAuthorizedCodeGrantAsWellWhenVerifiableCredentialIssuanceIsEnabled(): void
    {
        $this->expectGrantEnabledOnTheServer($this->authCodeGrantMock);
        $this->expectGrantEnabledOnTheServer($this->implicitGrantMock);
        $this->expectGrantEnabledOnTheServer($this->refreshTokenGrantMock);
        $this->expectGrantEnabledOnTheServer($this->preAuthCodeGrantMock);

        $this->sut(vciEnabled: true)->build();
    }


    /**
     * The server hands the grant which claims a token request the lifetime it was enabled with and its own
     * configured copy of the response type. The lifetime is pinned by identity; the copy is pinned by its
     * class, which is the double's own and which no other TokenResponse has.
     */
    #[DataProvider('tokenRequestGrantProvider')]
    public function testGivesTheGrantAnsweringATokenRequestTheAccessTokenDurationAndTheTokenResponse(
        GrantTypesEnum $grantType,
    ): void {
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        $grantResponse = $this->createMock(ResponseTypeInterface::class);
        $grantResponse->method('generateHttpResponse')->with($this->identicalTo($response))->willReturn($response);
        $handled = [];

        $grantMock = $this->grantMockFor($grantType);
        $grantMock->method('canRespondToAccessTokenRequest')->with($this->identicalTo($request))->willReturn(true);
        $grantMock->expects($this->once())->method('respondToAccessTokenRequest')->willReturnCallback(
            function (
                ServerRequestInterface $request,
                ResponseTypeInterface $responseType,
                DateInterval $accessTokenTtl,
            ) use (
                &$handled,
                $grantResponse,
            ): ResponseTypeInterface {
                $handled = [$request, $responseType, $accessTokenTtl];

                return $grantResponse;
            },
        );

        $server = $this->sut(vciEnabled: $grantType === GrantTypesEnum::PreAuthorizedCode)->build();

        $this->assertSame($response, $server->respondToAccessTokenRequest($request, $response));
        [$handledRequest, $responseType, $accessTokenTtl] = $handled;
        $this->assertSame($request, $handledRequest);
        $this->assertSame($this->tokenResponseMock::class, $responseType::class);
        $this->assertSame($this->accessTokenDuration, $accessTokenTtl);
    }


    /**
     * The grants which answer token requests; the implicit grant is enabled on the server but never does.
     */
    public static function tokenRequestGrantProvider(): array
    {
        return [
            'the authorization code grant' => [GrantTypesEnum::AuthorizationCode],
            'the refresh token grant' => [GrantTypesEnum::RefreshToken],
            'the pre-authorized code grant, with issuance enabled' => [GrantTypesEnum::PreAuthorizedCode],
        ];
    }
}
