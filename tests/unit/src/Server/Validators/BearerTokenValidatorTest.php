<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\unit\Server\Validators;

use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\AccessTokenEntity;
use SimpleSAML\Module\oidc\Entities\ClientEntity;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\AccessTokenRepository;
use SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException;
use SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\OpenID\Exceptions\JwsException;
use SimpleSAML\OpenID\Jwks;
use SimpleSAML\OpenID\Jws;
use SimpleSAML\OpenID\Jws\Factories\ParsedJwsFactory;
use SimpleSAML\OpenID\Jws\ParsedJws;

/**
 * @covers \SimpleSAML\Module\oidc\Server\Validators\BearerTokenValidator
 */
class BearerTokenValidatorTest extends TestCase
{
    protected MockObject $accessTokenRepositoryMock;
    protected array $accessTokenState;
    protected AccessTokenEntity $accessTokenEntityMock;
    protected string $accessToken;
    protected ClientEntityInterface $clientEntityMock;
    protected ServerRequestInterface $serverRequest;
    protected MockObject $publicKeyMock;
    protected MockObject $moduleConfigMock;
    protected MockObject $jwsMock;
    protected MockObject $jwksMock;
    protected MockObject $loggerServiceMock;
    protected MockObject $parsedJwsFactoryMock;
    protected MockObject $parsedJwsMock;
    protected string $clientId;

    /**
     * @throws \Exception
     */
    public function setUp(): void
    {
        $this->accessTokenRepositoryMock = $this->createMock(AccessTokenRepository::class);
        $this->serverRequest = new ServerRequest();
        $this->moduleConfigMock = $this->createMock(ModuleConfig::class);

        $this->jwsMock = $this->createMock(Jws::class);
        $this->jwksMock = $this->createMock(Jwks::class);
        $this->loggerServiceMock = $this->createMock(LoggerService::class);

        $this->clientEntityMock = $this->createMock(ClientEntity::class);
        $this->clientId = 'clientId';
        $this->clientEntityMock->method('getIdentifier')->willReturn($this->clientId);

        $this->accessTokenState = [
            'id' => 'accessToken123',
            'scopes' => '{"openid":"openid","profile":"profile"}',
            'expires_at' => date('Y-m-d H:i:s', time() + 60),
            'user_id' => 'user123',
            'client_id' => $this->clientId,
            'is_revoked' => false,
            'auth_code_id' => 'authCode123',
        ];

        $this->accessTokenEntityMock = $this->createMock(AccessTokenEntity::class);

        $this->accessToken = 'token';

        $this->parsedJwsFactoryMock = $this->createMock(ParsedJwsFactory::class);
        $this->jwsMock->method('parsedJwsFactory')->willReturn($this->parsedJwsFactoryMock);

        $this->parsedJwsMock = $this->createMock(ParsedJws::class);
        $this->parsedJwsMock->method('getJwtId')->willReturn('accessToken123');
        $this->parsedJwsMock->method('getAudience')->willReturn([$this->clientId]);
    }

    protected function sut(
        ?AccessTokenRepository $accessTokenRepository = null,
        ?ModuleConfig $moduleConfig = null,
        ?Jws $jws = null,
        ?Jwks $jwks = null,
        ?LoggerService $loggerService = null,
    ): BearerTokenValidator {
        $accessTokenRepository ??= $this->accessTokenRepositoryMock;
        $moduleConfig ??= $this->moduleConfigMock;
        $jws ??= $this->jwsMock;
        $jwks ??= $this->jwksMock;
        $loggerService ??= $this->loggerServiceMock;

        return new BearerTokenValidator(
            $accessTokenRepository,
            $moduleConfig,
            $jws,
            $jwks,
            $loggerService,
        );
    }

    public function testValidatorThrowsForNonExistentAccessToken()
    {
        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($this->serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForAuthorizationHeader()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $validatedServerRequest = $this->sut()->validateAuthorization($serverRequest);

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testValidatesForPostBodyParam()
    {
        $bodyArray = ['access_token' => $this->accessToken];
        $tempStream = (new StreamFactory())->createStream(http_build_query($bodyArray));

        $serverRequest = $this->serverRequest
            ->withMethod('POST')
            ->withAddedHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($tempStream)
            ->withParsedBody($bodyArray);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $validatedServerRequest = $this->sut()->validateAuthorization($serverRequest);

        $this->assertSame(
            $this->accessTokenState['id'],
            $validatedServerRequest->getAttribute('oauth_access_token_id'),
        );
    }

    public function testThrowsForUnparsableAccessToken()
    {
        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . 'invalid');

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with('invalid')
            ->willThrowException(new JwsException('Unparsable'));

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \Exception
     */
    public function testThrowsForRevokedAccessToken()
    {
        $this->accessTokenRepositoryMock->method('isAccessTokenRevoked')->willReturn(true);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($this->parsedJwsMock);

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     * @throws \JsonException
     */
    public function testThrowsForEmptyAccessTokenJti()
    {
        $accessToken = $this->createMock(ParsedJws::class);
        $this->parsedJwsFactoryMock->method('fromToken')
            ->with($this->accessToken)
            ->willReturn($accessToken);

        $serverRequest = $this->serverRequest->withAddedHeader('Authorization', 'Bearer ' . $this->accessToken);

        $this->expectException(OidcServerException::class);

        $this->sut()->validateAuthorization($serverRequest);
    }
}
