<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidc\Utils\Checker\Rules;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use SimpleSAML\Module\oidc\Entities\Interfaces\ClientEntityInterface;
use SimpleSAML\Module\oidc\ModuleConfig;
use SimpleSAML\Module\oidc\Repositories\ClientRepository;
use SimpleSAML\Module\oidc\Services\LoggerService;
use SimpleSAML\Module\oidc\Utils\Checker\Interfaces\ResultBagInterface;
use SimpleSAML\Module\oidc\Utils\Checker\Result;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\IdTokenHintRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule;
use SimpleSAML\Module\oidc\Utils\Checker\Rules\StateRule;
use Throwable;

/**
 * @covers \SimpleSAML\Module\oidc\Utils\Checker\Rules\PostLogoutRedirectUriRule
 */
class PostLogoutRedirectUriRuleTest extends TestCase
{
    protected Stub $clientRepositoryStub;
    protected Stub $requestStub;
    protected Stub $resultBagStub;
    protected Stub $clientStub;

    protected static string $certFolder;
    protected static string $privateKeyPath;
    protected static string $publicKeyPath;
    protected static CryptKey $privateKey;
    protected static CryptKey $publicKey;

    protected static string $postLogoutRedirectUri = 'https://redirect.org/uri';
    protected static string $issuer = 'https://example.org';
    private Configuration $jwtConfig;

    protected Stub $loggerServiceStub;

    public static function setUpBeforeClass(): void
    {
        self::$certFolder = dirname(__DIR__, 5) . '/docker/ssp/';
        self::$privateKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_PRIVATE_KEY_FILENAME;
        self::$publicKeyPath = self::$certFolder . ModuleConfig::DEFAULT_PKI_CERTIFICATE_FILENAME;
        self::$privateKey = new CryptKey(self::$privateKeyPath, null, false);
        self::$publicKey = new CryptKey(self::$publicKeyPath, null, false);
    }

    /**
     * @throws \Exception
     */
    protected function setUp(): void
    {
        $this->clientRepositoryStub = $this->createStub(ClientRepository::class);
        $this->requestStub = $this->createStub(ServerRequestInterface::class);
        $this->requestStub->method('getMethod')->willReturn('GET');
        $this->resultBagStub = $this->createStub(ResultBagInterface::class);
        $this->clientStub = $this->createStub(ClientEntityInterface::class);

        $this->jwtConfig = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(self::$privateKey->getKeyContents()),
            InMemory::plainText(self::$publicKey->getKeyContents()),
        );

        $this->loggerServiceStub = $this->createStub(LoggerService::class);
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleReturnsNullIfNoParamSet(): void
    {
        $result = (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));

        $this->assertNull($result->getValue());
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsWhenIdTokenHintNotAvailable(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $this->expectException(Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsWhenAudClaimNotValid(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()->issuedBy(self::$issuer)
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents()),
            );


        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt),
        );

        $this->expectException(Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsWhenClientNotFound(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('invalid-client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents()),
            );

        $this->clientRepositoryStub->method('findById')->willReturn(null);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt),
        );

        $this->expectException(Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));
    }

    /**
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleThrowsWhenPostLogoutRegisteredUriNotRegistered(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents()),
            );

        $this->clientStub->method('getPostLogoutRedirectUri')->willReturn([
            'https://some-other-uri',
        ]);

        $this->clientRepositoryStub->method('findById')->willReturn($this->clientStub);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt),
        );

        $this->expectException(Throwable::class);

        (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));
    }

    /**
     * @throws \Throwable
     * @throws \SimpleSAML\Module\oidc\Server\Exceptions\OidcServerException
     */
    public function testCheckRuleReturnsForRegisteredPostLogoutRedirectUri(): void
    {
        $this->requestStub->method('getQueryParams')
            ->willReturn(['post_logout_redirect_uri' => self::$postLogoutRedirectUri]);

        $jwt = $this->jwtConfig->builder()
            ->issuedBy(self::$issuer)
            ->permittedFor('client-id')
            ->getToken(
                new Sha256(),
                InMemory::plainText(self::$privateKey->getKeyContents()),
            );

        $this->clientStub->method('getPostLogoutRedirectUri')->willReturn([
            self::$postLogoutRedirectUri,
        ]);

        $this->clientRepositoryStub->method('findById')->willReturn($this->clientStub);

        $this->resultBagStub->method('getOrFail')->willReturnOnConsecutiveCalls(
            new Result(StateRule::class),
            new Result(IdTokenHintRule::class, $jwt),
        );

        $result = (new PostLogoutRedirectUriRule($this->clientRepositoryStub))
            ->checkRule($this->requestStub, $this->resultBagStub, $this->loggerServiceStub) ??
        (new Result(PostLogoutRedirectUriRule::class));

        $this->assertEquals(self::$postLogoutRedirectUri, $result->getValue());
    }
}
