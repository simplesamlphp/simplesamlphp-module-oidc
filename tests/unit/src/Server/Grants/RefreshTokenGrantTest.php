<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Grants;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Factories\Entities\AccessTokenEntityFactory;
use SimpleSAML\Module\oidc\Server\Grants\RefreshTokenGrant;
use SimpleSAML\Module\oidc\Server\TokenIssuers\RefreshTokenIssuer;
use SimpleSAML\Module\oidc\Utils\AuthenticatedOAuth2ClientResolver;
use SimpleSAML\Module\oidc\ValueAbstracts\ResolvedClientAuthenticationMethod;
use SimpleSAML\OpenID\Codebooks\ClientAuthenticationMethodsEnum;

#[CoversClass(RefreshTokenGrant::class)]
class RefreshTokenGrantTest extends TestCase
{
    protected MockObject $refreshTokenRepositoryMock;
    protected MockObject $accessTokenEntityFactoryMock;
    protected MockObject $refreshTokenIssuerMock;
    protected MockObject $clientResolverMock;
    protected MockObject $serverRequestMock;

    protected function setUp(): void
    {
        $this->refreshTokenRepositoryMock = $this->createMock(RefreshTokenRepositoryInterface::class);
        $this->accessTokenEntityFactoryMock = $this->createMock(AccessTokenEntityFactory::class);
        $this->refreshTokenIssuerMock = $this->createMock(RefreshTokenIssuer::class);
        $this->clientResolverMock = $this->createMock(AuthenticatedOAuth2ClientResolver::class);
        $this->serverRequestMock = $this->createMock(ServerRequestInterface::class);
    }

    protected function sut(): RefreshTokenGrant
    {
        return new RefreshTokenGrant(
            $this->refreshTokenRepositoryMock,
            $this->accessTokenEntityFactoryMock,
            $this->refreshTokenIssuerMock,
            $this->clientResolverMock,
        );
    }

    /**
     * @throws \ReflectionException
     */
    protected function callValidateClient(RefreshTokenGrant $grant): ClientEntity
    {
        $method = new \ReflectionMethod(RefreshTokenGrant::class, 'validateClient');

        /** @var ClientEntity $client */
        $client = $method->invoke($grant, $this->serverRequestMock);

        return $client;
    }

    /**
     * The refresh grant must authenticate the client via the resolver (which supports private_key_jwt,
     * client_secret_basic/post and public clients) rather than the league default that requires a client_id
     * request parameter.
     *
     * @throws \ReflectionException
     */
    public function testValidateClientResolvesClientWithoutRequiringClientIdParameter(): void
    {
        $clientMock = $this->createMock(ClientEntity::class);
        $this->clientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->serverRequestMock)
            ->willReturn(new ResolvedClientAuthenticationMethod(
                $clientMock,
                ClientAuthenticationMethodsEnum::PrivateKeyJwt,
            ));

        $this->assertSame($clientMock, $this->callValidateClient($this->sut()));
    }

    /**
     * When the client cannot be authenticated the grant must reject the request with an invalid_client error,
     * not fall back to the league default (which would demand a client_id parameter).
     *
     * @throws \ReflectionException
     */
    public function testValidateClientThrowsWhenClientCannotBeResolved(): void
    {
        $this->clientResolverMock->expects($this->once())
            ->method('forAnySupportedMethod')
            ->with($this->serverRequestMock)
            ->willReturn(null);

        $this->expectException(OAuthServerException::class);

        $this->callValidateClient($this->sut());
    }
}
